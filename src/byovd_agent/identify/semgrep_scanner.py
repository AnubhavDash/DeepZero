from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

from byovd_agent.models import SemgrepFinding, Severity

log = logging.getLogger(__name__)

RULES_DIR = Path(__file__).parent / "rules"


def run_semgrep(target_dir: Path) -> list[SemgrepFinding]:
    """run all semgrep rules against decompiled C files in a directory"""
    c_files = list(target_dir.rglob("*.c"))
    if not c_files:
        log.warning("no .c files found in %s", target_dir)
        return []

    cmd = [
        "semgrep", "scan",
        "--config", str(RULES_DIR),
        "--json",
        "--no-git-ignore",
        "--quiet",
        "--metrics=off",
        "--disable-version-check",
        str(target_dir),
    ]

    log.info("running semgrep on %d files in %s", len(c_files), target_dir)

    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=120)
    except FileNotFoundError:
        log.error("semgrep not found — install with: pip install semgrep")
        return []
    except subprocess.TimeoutExpired:
        log.error("semgrep timed out")
        return []

    if proc.returncode not in (0, 1):
        err = proc.stderr.decode('utf-8', errors='replace')[:500]
        log.error("semgrep failed: %s", err)
        return []

    try:
        out_str = proc.stdout.decode('utf-8', errors='replace')
        output = json.loads(out_str) if out_str.strip() else {}
    except json.JSONDecodeError:
        log.error("failed to parse semgrep output")
        return []

    findings: list[SemgrepFinding] = []
    for result in output.get("results", []):
        sev_map = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}
        raw_sev = result.get("extra", {}).get("severity", "WARNING")

        # try to extract ioctl code from the file path
        ioctl_code = ""
        fpath = result.get("path", "")
        if "0x" in Path(fpath).stem:
            ioctl_code = Path(fpath).stem

        finding = SemgrepFinding(
            rule_id=result.get("check_id", ""),
            severity=sev_map.get(raw_sev, Severity.MEDIUM),
            message=result.get("extra", {}).get("message", ""),
            file_path=fpath,
            line_start=result.get("start", {}).get("line", 0),
            line_end=result.get("end", {}).get("line", 0),
            matched_code=result.get("extra", {}).get("lines", ""),
            ioctl_code=ioctl_code,
        )
        findings.append(finding)

    log.info("semgrep found %d issues", len(findings))
    return findings


def _estimate_tokens(text: str) -> int:
    """rough token estimate: ~4 chars per token for C code"""
    return len(text) // 4


def _trim_dispatch_to_budget(decompiled_c: str, char_budget: int) -> str:
    """trim deep subfunctions from dispatch code while preserving the entry handler.
    the dispatch_ioctl.c file has a structure:
      1. the main dispatch handler (entry point)
      2. a separator comment block
      3. all called subfunctions appended sequentially

    we keep the main handler intact and trim subfunctions from the bottom
    until the result fits within the character budget.
    """
    if len(decompiled_c) <= char_budget:
        return decompiled_c

    # split on the subfunction separator that ghidra_runner inserts
    separator = "// ======================================== //"
    sep_idx = decompiled_c.find(separator)

    if sep_idx == -1:
        # no separator found, just hard-truncate
        return decompiled_c[:char_budget] + f"\n... [truncated to fit token budget, {len(decompiled_c)} total chars]"

    # the main dispatch handler is everything before the separator block
    # find the end of the separator block (three lines)
    header_end = decompiled_c.find("\n", decompiled_c.find("\n", decompiled_c.find("\n", sep_idx) + 1) + 1)
    if header_end == -1:
        header_end = sep_idx

    main_handler = decompiled_c[:sep_idx]
    subfunctions_block = decompiled_c[header_end:]

    # split subfunctions on double-newline boundaries (each function is separated by blank lines)
    subfunctions = subfunctions_block.split("\n\n\n")

    # greedily add subfunctions until we'd exceed the budget
    remaining_budget = char_budget - len(main_handler) - 200  # reserve space for separator + truncation note
    kept_parts = [main_handler, separator]

    chars_used = 0
    kept_count = 0
    for sf in subfunctions:
        if not sf.strip():
            continue
        if chars_used + len(sf) + 3 > remaining_budget:
            break
        kept_parts.append(sf)
        chars_used += len(sf) + 3
        kept_count += 1

    total_subfunctions = sum(1 for sf in subfunctions if sf.strip())
    if kept_count < total_subfunctions:
        kept_parts.append(
            f"\n... [{total_subfunctions - kept_count} subfunctions trimmed to fit token budget]"
        )

    return "\n\n\n".join(kept_parts[:2]) + "\n\n\n".join(kept_parts[2:])


def format_for_llm(
    findings: list[SemgrepFinding],
    decompiled_c: str = "",
    decompiled_dir: Path | None = None,
    max_tokens: int = 900_000,
) -> str:
    """format semgrep results + decompiled code for the LLM vuln reasoning step.

    the dispatch code is the primary source of truth and always gets priority.
    semgrep findings are included as compact one-line hints (rule + line number)
    since the LLM already has the full code to analyze. context windows are
    omitted to avoid payload explosion on drivers with thousands of findings.
    """
    parts: list[str] = []

    # semgrep findings as compact hints — no context windows, no code duplication
    if findings:
        # deduplicate by (rule_id, file, line) to collapse noisy repeated matches
        seen: set[tuple[str, str, int]] = set()
        unique: list[SemgrepFinding] = []
        for f in findings:
            key = (f.rule_id, Path(f.file_path).name if f.file_path else "", f.line_start)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        parts.append(f"=== SEMGREP HINTS: {len(unique)} unique findings (from {len(findings)} raw) ===\n")

        for i, f in enumerate(unique, 1):
            location = f""
            if f.file_path:
                location = f" @ {Path(f.file_path).name}:{f.line_start}"
            ioctl = f" IOCTL={f.ioctl_code}" if f.ioctl_code else ""
            parts.append(f"  [{i}] {f.severity.value} {f.rule_id}{location}{ioctl}")
        parts.append("")
    else:
        parts.append("=== SEMGREP: no pattern-based findings ===\n")

    # dispatch code is the primary payload — gets the bulk of the token budget
    if decompiled_c:
        parts.append("=== DECOMPILED DISPATCH HANDLER + SUBFUNCTIONS ===\n")

        # calculate remaining budget after the hints section
        hints_text = "\n".join(parts)
        hints_tokens = _estimate_tokens(hints_text)
        code_token_budget = max_tokens - hints_tokens - 2000  # reserve for prompt framing
        code_char_budget = code_token_budget * 4

        trimmed = _trim_dispatch_to_budget(decompiled_c, code_char_budget)
        parts.append(trimmed)

    return "\n".join(parts)
