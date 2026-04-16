from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from deepzero.engine.stage import Sample, BulkMapProcessor, ProcessorResult, ProcessorContext


class SemgrepScanner(BulkMapProcessor):
    description = "runs semgrep batch scan against decompiled source across all active samples"

    def validate(self) -> list[str]:
        if not shutil.which("semgrep"):
            return ["semgrep CLI not found in PATH - install with: pip install semgrep"]
        return []

    def process(self, ctx: ProcessorContext, entries: list[Sample]) -> list[ProcessorResult]:
        rules_dir = self.config.get("rules_dir")
        if not rules_dir:
            return [ProcessorResult.fail("semgrep_scanner requires 'rules_dir' in config")] * len(entries)

        rules_path = (Path.cwd() / rules_dir).resolve()
        if not rules_path.exists():
            return [ProcessorResult.fail(f"semgrep rules dir not found: {rules_path}")] * len(entries)

        target_subdir = self.config.get("target_dir", "decompiled")
        timeout = self.config.get("timeout", 300)
        min_findings = self.config.get("min_findings", 0)

        results: list[ProcessorResult | None] = [None] * len(entries)
        uncached_entries: list[tuple[int, Sample]] = []

        for i, entry in enumerate(entries):
            findings_path = entry.sample_dir / "findings.json"
            if findings_path.exists():
                try:
                    findings = json.loads(findings_path.read_text(encoding="utf-8"))
                    results[i] = self._make_result(findings, min_findings, cached=True)
                    continue
                except (json.JSONDecodeError, OSError) as exc:
                    self.log.debug("cache read failed for %s, rescanning: %s", entry.sample_id, exc)

            scan_dir = entry.sample_dir / target_subdir
            if not scan_dir.exists():
                results[i] = ProcessorResult.fail(
                    f"scan target '{target_subdir}' missing - does a decompile processor run before this?"
                )
                continue

            uncached_entries.append((i, entry))

        if not uncached_entries:
            return [r for r in results if r is not None]

        bulk_dir = entries[0].sample_dir.parent.parent / ".bulk_temp" / "semgrep"
        if bulk_dir.exists():
            shutil.rmtree(bulk_dir, ignore_errors=True)
        bulk_dir.mkdir(parents=True, exist_ok=True)

        file_to_sample: dict[str, int] = {}

        for idx, entry in uncached_entries:
            scan_dir = entry.sample_dir / target_subdir
            for src_file in scan_dir.rglob("*"):
                if not src_file.is_file():
                    continue
                if src_file.suffix not in (".c", ".h", ".cpp", ".py"):
                    continue
                dest_name = f"{entry.sample_id}_{src_file.name}"
                dest = bulk_dir / dest_name
                try:
                    os.link(src_file, dest)
                except OSError:
                    shutil.copy2(src_file, dest)
                file_to_sample[dest_name] = idx

        if not file_to_sample:
            for idx, _entry in uncached_entries:
                results[idx] = ProcessorResult.ok(
                    data={"finding_count": 0, "findings_cached": False},
                )
            self._cleanup_bulk_dir(bulk_dir)
            return [r for r in results if r is not None]

        cmd = [
            "semgrep", "scan",
            "--config", str(rules_path),
            "--json",
            "--no-git-ignore",
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
            str(bulk_dir),
        ]

        self.log.info("bulk scanning %d files from %d samples", len(file_to_sample), len(uncached_entries))

        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
        except FileNotFoundError:
            self._cleanup_bulk_dir(bulk_dir)
            for idx, _ in uncached_entries:
                results[idx] = ProcessorResult.fail("semgrep not installed - pip install semgrep")
            return [r for r in results if r is not None]
        except subprocess.TimeoutExpired:
            self._cleanup_bulk_dir(bulk_dir)
            for idx, _ in uncached_entries:
                results[idx] = ProcessorResult.fail(f"semgrep batch timed out after {timeout}s")
            return [r for r in results if r is not None]

        if proc.returncode not in (0, 1):
            err = proc.stderr.decode("utf-8", errors="replace")[:500]
            self._cleanup_bulk_dir(bulk_dir)
            for idx, _ in uncached_entries:
                results[idx] = ProcessorResult.fail(f"semgrep error: {err}")
            return [r for r in results if r is not None]

        try:
            out_str = proc.stdout.decode("utf-8", errors="replace")
            output = json.loads(out_str) if out_str.strip() else {}
        except json.JSONDecodeError:
            self._cleanup_bulk_dir(bulk_dir)
            for idx, _ in uncached_entries:
                results[idx] = ProcessorResult.fail("failed to parse semgrep json output")
            return [r for r in results if r is not None]

        sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
        per_sample_findings: dict[int, list[dict]] = {idx: [] for idx, _ in uncached_entries}

        for result_entry in output.get("results", []):
            file_path = result_entry.get("path", "")
            filename = Path(file_path).name

            sample_idx = file_to_sample.get(filename)
            if sample_idx is None:
                continue

            raw_sev = result_entry.get("extra", {}).get("severity", "WARNING")
            finding: dict[str, Any] = {
                "rule_id": result_entry.get("check_id", ""),
                "severity": sev_map.get(raw_sev, "MEDIUM"),
                "message": result_entry.get("extra", {}).get("message", ""),
                "file": result_entry.get("path", ""),
                "line_start": result_entry.get("start", {}).get("line", 0),
                "line_end": result_entry.get("end", {}).get("line", 0),
                "matched_code": result_entry.get("extra", {}).get("lines", ""),
            }
            per_sample_findings[sample_idx].append(finding)

        for idx, entry in uncached_entries:
            findings = per_sample_findings.get(idx, [])
            findings_path = entry.sample_dir / "findings.json"
            fd, tmp = tempfile.mkstemp(dir=str(entry.sample_dir), suffix=".json")
            try:
                os.write(fd, json.dumps(findings, indent=2).encode("utf-8"))
                os.close(fd)
                os.replace(tmp, str(findings_path))
            except OSError:
                try:
                    os.close(fd)
                except OSError:
                    pass
                self.log.debug("failed to write findings for %s", entry.sample_id)
            results[idx] = self._make_result(findings, min_findings, cached=False)

        self._cleanup_bulk_dir(bulk_dir)
        return [r for r in results if r is not None]

    def _make_result(self, findings: list[dict], min_findings: int, cached: bool) -> ProcessorResult:
        data: dict[str, Any] = {"finding_count": len(findings), "findings_cached": cached}

        if min_findings > 0 and len(findings) < min_findings:
            return ProcessorResult.filter(
                f"{len(findings)} findings < min {min_findings}",
                data={**data, "findings": "findings.json"},
            )

        return ProcessorResult.ok(
            artifacts={"findings": "findings.json"},
            data=data,
        )

    def _cleanup_bulk_dir(self, bulk_dir: Path) -> None:
        try:
            shutil.rmtree(bulk_dir, ignore_errors=True)
        except OSError:
            self.log.debug("batch dir cleanup failed: %s", bulk_dir)
