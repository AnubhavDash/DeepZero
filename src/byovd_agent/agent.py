from __future__ import annotations

import json
import logging
from pathlib import Path

from langchain_core.tools import tool
from rich.console import Console

from deepagents import create_deep_agent

from byovd_agent.config import Config
from byovd_agent.identify.semgrep_scanner import format_for_llm, run_semgrep
from byovd_agent.ingest.scraper import scan_for_sys_files, scan_priority_packs
from byovd_agent.ingest.triage import batch_triage, triage_driver
from byovd_agent.knowledge.loldrivers import LOLDriversDB
from byovd_agent.prompts import ORCHESTRATOR_PROMPT
from byovd_agent.translate.ghidra_runner import run_ghidra_headless

log = logging.getLogger(__name__)

# module-level refs set by create_agent before tools are called
_config: Config | None = None
_loldb: LOLDriversDB | None = None


@tool
def triage_drivers(directory: str, max_results: int = 50) -> str:
    """triage all .sys files in a directory. checks each driver for
    kernel subsystem, IOCTL surface, signing status, and dangerous imports.
    deduplicates against the LOLDrivers known-vulnerability database.
    returns the top candidates sorted by priority score as JSON.

    Args:
        directory: path to a directory containing .sys files, or a single .sys file
        max_results: maximum number of passed candidates to return
    """
    target = Path(directory)

    if target.is_file() and target.suffix.lower() == ".sys":
        result = triage_driver(target)
        if _loldb and _loldb.is_known(result.sha256):
            result.is_known_vuln = True
            result.reject_reason = "already known in LOLDrivers"
            result.passed_triage = False
        return result.model_dump_json(indent=2)

    # check if this looks like an SDIO root with pack subdirectories
    subdirs = [d for d in target.iterdir() if d.is_dir()] if target.is_dir() else []
    has_packs = any("DP_" in d.name for d in subdirs)

    if has_packs:
        sys_files = scan_priority_packs(target, priority_only=True)
    else:
        sys_files = scan_for_sys_files(target)

    if not sys_files:
        return f"no .sys files found in {directory}"

    known = _loldb._sha256_set if _loldb else set()
    results = batch_triage(sys_files, known, cache_dir=_config.work_dir if _config else None)

    passed = [r for r in results if r.passed_triage][:max_results]

    console = Console()
    console.print("\n[bold green]=== Triage Phase Complete ===[/]")
    console.print(f"[bold]Total .sys Files Scanned:[/] {len(sys_files)}")
    console.print(f"[bold]Vulnerable Candidates Located:[/] {len([r for r in results if r.passed_triage])}")
    console.print(f"[bold]Drivers Rejected (Safe/Known):[/] {len([r for r in results if not r.passed_triage])}")
    console.print(f"[bold]Candidates Queued for Analysis:[/] {len(passed)}\n")

    # build a compact summary for the LLM
    output = {
        "total_scanned": len(sys_files),
        "passed_triage": len([r for r in results if r.passed_triage]),
        "rejected": len([r for r in results if not r.passed_triage]),
        "top_candidates": [
            {
                "path": r.path,
                "filename": r.filename,
                "sha256": r.sha256,
                "machine_type": r.machine_type,
                "priority_score": r.priority_score,
                "vuln_classes": [v.value for v in r.detected_vuln_classes],
                "dangerous_imports": r.dangerous_imports[:10],
                "is_signed": r.is_signed,
            }
            for r in passed
        ],
    }
    return json.dumps(output, indent=2, default=str)


@tool
def batch_analyze_candidates(candidates_json: str) -> str:
    """Run Ghidra decompilation and Semgrep vulnerability scanning on a batch of candidates natively.
    This prevents agent loop limitations by handling all processing inside Python.
    
    Args:
        candidates_json: A JSON string containing a list of objects, each with 'path' and 'sha256' keys.
    """
    try:
        candidates = json.loads(candidates_json)
    except json.JSONDecodeError:
        return "error: invalid JSON provided for batch analysis"

    if not isinstance(candidates, list):
        return "error: expected a list of candidates"

    all_findings = []
    
    for c in candidates:
        sys_path = Path(c.get("path", ""))
        sha256 = c.get("sha256", "")
        
        if not sys_path.exists():
            continue
            
        work_name = sha256[:16] if sha256 else sys_path.stem
        work_dir = _config.work_dir / work_name
        work_dir.mkdir(parents=True, exist_ok=True)
        
        # 1. run ghidra
        result = run_ghidra_headless(
            sys_path, work_dir, _config.ghidra_install_dir
        )
        
        result_path = work_dir / "translation_result.json"
        result_path.write_text(result.model_dump_json(indent=2))
        
        if not result.success:
            all_findings.append(f"--- {sys_path.name} ---\nghidra failed: {result.error}\n")
            continue
            
        # 2. run semgrep
        decompiled_dir = work_dir / "decompiled"
        if not decompiled_dir.exists():
            continue
            
        findings = run_semgrep(decompiled_dir)
        if not findings:
            continue
            
        dispatch_c = ""
        dispatch_file = decompiled_dir / "dispatch_ioctl.c"
        if dispatch_file.exists():
            dispatch_c = dispatch_file.read_text(encoding="utf-8", errors="replace")
            
        formatted = format_for_llm(findings, dispatch_c)
        
        summary = [
            f"--- {sys_path.name} ---",
            f"device: {result.device_name}",
            f"dispatch handler: {result.dispatch_function_name}",
            f"{formatted}"
        ]
        all_findings.append("\n".join(summary))

    if not all_findings:
        return "no vulnerabilities found in any of the candidates."
        
    return "\n\n".join(all_findings)


def create_agent(config: Config):
    """build the DeepAgents agent with all tools"""
    global _config, _loldb

    _config = config
    _loldb = LOLDriversDB(config.loldrivers_db)
    log.info("loaded LOLDrivers DB: %d entries, %d hashes", _loldb.total_entries, _loldb.total_hashes)

    agent = create_deep_agent(
        model=config.model,
        tools=[triage_drivers, batch_analyze_candidates],
        system_prompt=ORCHESTRATOR_PROMPT,
        name="byovd-orchestrator",
    )

    return agent
