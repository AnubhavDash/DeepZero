from __future__ import annotations

import argparse
import logging
import sys

from rich.console import Console
from rich.logging import RichHandler

from byovd_agent.agent import create_agent
from byovd_agent.config import Config

console = Console()


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, show_path=False, markup=True)],
        force=True,
    )
    # suppress noisy libraries unless verbose
    if not verbose:
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)


def _extract_response(result: dict) -> str:
    """pull the last AI message from the agent result"""
    out_messages = result.get("messages", [])
    
    def _parse_content(content) -> str:
        if isinstance(content, list):
            parts = []
            for c in content:
                if isinstance(c, dict):
                    parts.append(c.get("text", ""))
                else:
                    parts.append(str(c))
            return "".join(parts)
        return str(content)

    for msg in reversed(out_messages):
        if hasattr(msg, "content"):
            msg_type = getattr(msg, "type", "")
            if msg_type == "ai" and msg.content:
                return _parse_content(msg.content)
        elif isinstance(msg, dict):
            if msg.get("role") == "assistant" and msg.get("content"):
                return _parse_content(msg["content"])

    # fallback: dump what we got
    return (
        f"[agent returned no AI message — keys: {list(result.keys())}, "
        f"message count: {len(out_messages)}]"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="autonomous vulnerability research agent for Windows kernel drivers",
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="",
        help="path to a .sys file, directory of .sys files, or SDIO packs directory",
    )
    parser.add_argument(
        "--model", default="", help="override LLM model (e.g., vertexai:gemini-2.5-pro)",
    )
    parser.add_argument(
        "--interactive", "-i", action="store_true",
        help="run in interactive chat mode instead of processing a target",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="enable debug logging",
    )
    parser.add_argument(
        "--env", default=None, help="path to .env file",
    )
    parser.add_argument(
        "--limit", type=int, default=0, help="maximum number of uncached candidates to sequentially process this run (0 for infinite)",
    )
    args = parser.parse_args()

    setup_logging(args.verbose)
    log = logging.getLogger("byovd_agent")

    config = Config.from_env(args.env)
    if args.model:
        config.model = args.model
    config.ensure_dirs()

    console.print("[bold cyan]byovd-agent[/] — autonomous driver vulnerability research")
    console.print(f"  model:      {config.model}")
    console.print(f"  ghidra:     {config.ghidra_install_dir}")
    console.print(f"  loldrivers: {config.loldrivers_db}")
    console.print(f"  work_dir:   {config.work_dir}")
    console.print()

    agent = create_agent(config)

    if args.interactive or not args.target:
        console.print("[dim]interactive mode — type your instructions[/]")
        console.print("[dim]example: 'triage all .sys files in samples/ and analyze the top 5'[/]")
        console.print()

        messages = []
        while True:
            try:
                user_input = console.input("[bold green]> [/]")
            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim]exiting[/]")
                break

            if not user_input.strip():
                continue
            if user_input.strip().lower() in ("exit", "quit", "q"):
                break

            messages.append({"role": "user", "content": user_input})

            console.print()
            log.info("[agent] processing request...")
            result = agent.invoke({"messages": messages})
            response = _extract_response(result)
            console.print(f"\n[bold cyan]agent:[/] {response}\n")
            messages.append({"role": "assistant", "content": response})
    else:
        target = args.target
        console.print(f"[bold]target:[/] {target}")
        console.print()

        log.info(" starting native analysis pipeline execution...")
        
        from byovd_agent.ingest.scraper import scan_priority_packs, scan_for_sys_files
        from byovd_agent.ingest.triage import batch_triage
        from byovd_agent.knowledge.loldrivers import LOLDriversDB
        from byovd_agent.translate.ghidra_runner import run_ghidra_headless
        from byovd_agent.identify.semgrep_scanner import run_semgrep, format_for_llm
        import concurrent.futures
        from pathlib import Path
        import os

        target_path = Path(target)
        if target_path.is_dir() and any("DP_" in d.name for d in target_path.iterdir() if d.is_dir()):
            sys_files = scan_priority_packs(target_path, priority_only=True)
        else:
            sys_files = scan_for_sys_files(target_path)
            
        loldb = LOLDriversDB(config.loldrivers_db)
        results = batch_triage(sys_files, loldb._sha256_set, cache_dir=config.work_dir)
        
        # triage rejection breakdown — show exactly why drivers were filtered
        triage_passed_total = sum(1 for r in results if r.passed_triage)
        triage_rejected = [r for r in results if not r.passed_triage]
        reject_reasons: dict[str, int] = {}
        for r in triage_rejected:
            reason = r.reject_reason or "unknown"
            # normalize common reasons into buckets
            if "not a kernel driver" in reason:
                bucket = "not a kernel driver"
            elif "Legacy OS" in reason or "Legacy" in reason:
                bucket = "legacy OS version (pre-Win10)"
            elif "no user-reachable IOCTL" in reason:
                bucket = "no IOCTL attack surface"
            elif "unsigned" in reason:
                bucket = "unsigned driver"
            elif "LOLDrivers" in reason or "already known" in reason:
                bucket = "already in LOLDrivers DB"
            elif "invalid PE" in reason:
                bucket = "invalid PE format"
            elif "cannot read" in reason:
                bucket = "unreadable file"
            else:
                bucket = reason
            reject_reasons[bucket] = reject_reasons.get(bucket, 0) + 1

        # funnel highest priority candidates, tracking every skip
        candidate_queue = sorted([r for r in results if r.passed_triage], key=lambda x: x.priority_score, reverse=True)
        passed = []
        skip_has_report = 0
        skip_sha256_dup = 0
        seen_hashes: set[str] = set()
        skipped_report_names: list[str] = []
        for r in candidate_queue:
            # sha256 dedup — identical binaries in multiple pack dirs
            if r.sha256 and r.sha256 in seen_hashes:
                skip_sha256_dup += 1
                continue
            if r.sha256:
                seen_hashes.add(r.sha256)

            work_name = r.sha256[:16] if r.sha256 else Path(r.path).stem
            work_d = config.work_dir / work_name
            if (work_d / "VULNERABLE_report.md").exists() or (work_d / "SAFE_report.md").exists() or (work_d / "report.md").exists():
                skip_has_report += 1
                skipped_report_names.append(r.filename)
                continue

            passed.append(r)
            if args.limit and len(passed) >= args.limit:
                break
                
        console.print(f"\n[bold green]=== Native Triage Complete ===[/]")
        console.print(f"Total .sys Scanned: [bold]{len(sys_files)}[/]")
        console.print(f"Passed Triage:      [bold green]{triage_passed_total}[/]")
        console.print(f"Rejected by Triage: [dim]{len(triage_rejected)}[/]")

        if reject_reasons:
            console.print(f"\n[bold yellow]  Triage Rejection Breakdown:[/]")
            for reason, count in sorted(reject_reasons.items(), key=lambda x: -x[1]):
                console.print(f"    {count:>5}  {reason}")

        console.print(f"\n[bold cyan]  Post-Triage Filtering:[/]")
        console.print(f"    Candidates passed triage:   {triage_passed_total}")
        console.print(f"    Identical SHA256 (deduped):  {skip_sha256_dup} (skipped)")
        console.print(f"    Already have report:        {skip_has_report} (skipped)")
        console.print(f"    [bold]New candidates to analyze:  {len(passed)}[/]")

        if skip_has_report > 0 and args.verbose:
            console.print(f"\n  [dim]Drivers with existing reports (first 20):[/]")
            for name in skipped_report_names[:20]:
                console.print(f"    [dim]  ✓ {name}[/]")
            if len(skipped_report_names) > 20:
                console.print(f"    [dim]  ... and {len(skipped_report_names) - 20} more[/]")

        if not passed:
            console.print(f"\n[bold yellow]No new candidates to process.[/]")
            if skip_has_report > 0:
                console.print(f"[dim]All {triage_passed_total} triage-passing drivers already have reports in the work directory.[/]")
                console.print(f"[dim]To re-analyze, delete the VULNERABLE_report.md / SAFE_report.md / report.md files from work/.[/]")
            elif triage_passed_total == 0:
                console.print(f"[dim]Zero drivers passed triage. See rejection breakdown above.[/]")
            return

        console.print(f"\n[dim]Deploying analysis pool ({len(passed)} drivers)...[/]")
        
        all_findings = []
        # per-candidate disposition tracking
        # each entry: (driver_name, work_id, status, detail)
        import threading
        _log_lock = threading.Lock()
        candidate_log: list[tuple[str, str, str, str]] = []
        drop_counters: dict[str, int] = {
            "ghidra_failed": 0,
            "no_decompiled_dir": 0,
            "semgrep_zero_findings": 0,
            "no_dispatch_handler": 0,
            "exception": 0,
            "promoted_to_llm": 0,
        }
        
        def _record(driver_name, work_name, status, detail, counter_key):
            with _log_lock:
                candidate_log.append((driver_name, work_name, status, detail))
                drop_counters[counter_key] += 1

        def process_candidate(r):
            import json
            driver_name = Path(r.path).name
            work_name = r.sha256[:16] if r.sha256 else Path(r.path).stem
            work_dir = config.work_dir / work_name
            work_dir.mkdir(parents=True, exist_ok=True)
            
            result_path = work_dir / "translation_result.json"
            semgrep_cache = work_dir / "semgrep_results.json"
            
            if result_path.exists():
                log.info(f" [{work_name}] {driver_name} Ghidra translation explicitly restored")
            else:
                log.info(f"[{work_name}] starting Ghidra analysis of {driver_name} (timeout=300s)")
                result = run_ghidra_headless(Path(r.path), work_dir, config.ghidra_install_dir)
                result_path.write_text(result.model_dump_json(indent=2))
                if not result.success:
                    reason = result.error or "unknown ghidra error"
                    log.warning(f"[{work_name}] ✗ {driver_name} — ghidra failed: {reason[:120]}")
                    _record(driver_name, work_name, "DROPPED", f"ghidra failed: {reason[:80]}", "ghidra_failed")
                    return None
                    
            decompiled_dir = work_dir / "decompiled"
            if not decompiled_dir.exists():
                log.warning(f"[{work_name}] ✗ {driver_name} — no decompiled/ directory produced")
                _record(driver_name, work_name, "DROPPED", "no decompiled/ directory", "no_decompiled_dir")
                return None
                
            if semgrep_cache.exists():
                try:
                    from byovd_agent.identify.semgrep_scanner import SemgrepFinding
                    raw_data = json.loads(semgrep_cache.read_text())
                    findings = [SemgrepFinding(**x) for x in raw_data]
                except Exception:
                    findings = []
                    
                if not findings:
                    log.info(f"[{work_name}] ✗ {driver_name} — zero semgrep findings (cached)")
                    _record(driver_name, work_name, "DROPPED", "zero semgrep findings (no suspicious patterns)", "semgrep_zero_findings")
                    return None
            else:
                findings = run_semgrep(decompiled_dir)
                try:
                    semgrep_cache.write_text(json.dumps([f.model_dump(mode='json') for f in findings]))
                except Exception as e:
                    log.error(f"failed to serialize semgrep findings: {e}")
                    semgrep_cache.write_text("[]")
                    
                if not findings:
                    log.info(f"[{work_name}] ✗ {driver_name} — zero semgrep findings (fresh scan)")
                    _record(driver_name, work_name, "DROPPED", "zero semgrep findings (no suspicious patterns)", "semgrep_zero_findings")
                    return None
                    
            dispatch_c = ""
            dispatch_file = decompiled_dir / "dispatch_ioctl.c"
            if dispatch_file.exists():
                dispatch_c = dispatch_file.read_text(encoding="utf-8", errors="replace")
                
            formatted = format_for_llm(findings, dispatch_c, decompiled_dir)
            
            device_name = "unknown"
            handler_name = "unknown"
            symbolic_link = ""
            if result_path.exists():
                try:
                    js = json.loads(result_path.read_text())
                    device_name = js.get("device_name", "unknown")
                    handler_name = js.get("dispatch_function_name", "unknown")
                    symbolic_link = js.get("symbolic_link", "")
                except Exception:
                    pass
            
            log.info(
                f"[{work_name}] ✓ {driver_name} — {len(findings)} semgrep hits, "
                f"device={device_name}, link={symbolic_link or 'none'}"
            )
            _record(driver_name, work_name, "PROMOTED", f"{len(findings)} semgrep findings → LLM queue", "promoted_to_llm")
            return f"--- {work_name} ({driver_name}) ---\ndevice: {device_name}\nhandler: {handler_name}\n{formatted}"

        max_workers = min(4, os.cpu_count() or 1)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_r = {executor.submit(process_candidate, r): r for r in passed}
                completed = 0
                for future in concurrent.futures.as_completed(future_to_r):
                    completed += 1
                    r = future_to_r[future]
                    try:
                        res = future.result()
                        if res:
                            all_findings.append(res)
                    except Exception as exc:
                        driver_name = Path(r.path).name
                        work_name = r.sha256[:16] if r.sha256 else Path(r.path).stem
                        log.error(f"[{work_name}] ✗ {driver_name} — exception: {exc}")
                        _record(driver_name, work_name, "ERROR", str(exc)[:80], "exception")
                    if completed % 10 == 0 or completed == len(passed):
                        console.print(f"[dim]Processed {completed}/{len(passed)} candidates...[/]")
        except KeyboardInterrupt:
            console.print("\n[bold red][!] Aborted by user. Forcibly terminating pipeline and all child nodes...[/]")
            import os as _os
            import subprocess as _sp
            _sp.run(["taskkill", "/F", "/T", "/PID", str(_os.getpid())], capture_output=True)
            _os._exit(1)

        # print detailed processing summary
        console.print(f"\n[bold cyan]=== Processing Summary ===[/]")
        console.print(f"  Candidates processed:       {len(passed)}")
        console.print(f"  Promoted to LLM analysis:   [bold green]{drop_counters['promoted_to_llm']}[/]")
        console.print(f"  Dropped — ghidra failed:    {drop_counters['ghidra_failed']}")
        console.print(f"  Dropped — no decompiled/:   {drop_counters['no_decompiled_dir']}")
        console.print(f"  Dropped — 0 semgrep hits:   {drop_counters['semgrep_zero_findings']}")
        console.print(f"  Dropped — exceptions:       {drop_counters['exception']}")

        if candidate_log:
            console.print(f"\n[bold]  Per-Driver Disposition:[/]")
            for driver_name, work_id, status, detail in candidate_log:
                if status == "PROMOTED":
                    console.print(f"    [green]✓[/] {driver_name:<35} [{work_id}] {detail}")
                elif status == "ERROR":
                    console.print(f"    [red]✗[/] {driver_name:<35} [{work_id}] {detail}")
                else:
                    console.print(f"    [yellow]–[/] {driver_name:<35} [{work_id}] {detail}")

        console.print(f"\n[bold green]Extraction complete. {len(all_findings)} drivers promoted to LLM deep analysis.[/]")
        
        if not all_findings:
            console.print("\n[bold yellow]No drivers reached the LLM analysis stage.[/]")
            console.print("[dim]This means every candidate was filtered before reaching the AI. Common causes:[/]")
            if drop_counters["semgrep_zero_findings"] > 0:
                console.print(f"[dim]  • {drop_counters['semgrep_zero_findings']} drivers had zero semgrep pattern matches (no MmMapIoSpace, memcpy, etc. in decompiled code)[/]")
            if drop_counters["ghidra_failed"] > 0:
                console.print(f"[dim]  • {drop_counters['ghidra_failed']} drivers failed Ghidra decompilation[/]")
            if drop_counters["no_decompiled_dir"] > 0:
                console.print(f"[dim]  • {drop_counters['no_decompiled_dir']} drivers produced no decompilation output[/]")
            if skip_has_report > 0:
                console.print(f"[dim]  • {skip_has_report} drivers already had reports (skipped before processing)[/]")
            console.print(f"[dim]  To force re-analysis of previously-reported drivers, delete their report files from work/[/]")
            return
            
        # Export all findings securely to disk to prevent context destruction
        import json
        queue_path = Path("actionable_queue.json")
        queue_path.write_text(json.dumps(all_findings, indent=2))
        console.print(f"[dim]Saved all {len(all_findings)} hits to actionable_queue.json...[/]")
        
        import time
        llm_findings = all_findings
        console.print(f"\n[bold cyan]Generating Assessment Reports for {len(llm_findings)} candidates...[/]")
        
        # adaptive backoff — starts fast, increases only on rate limit errors
        backoff_seconds = 2.0
        
        for idx, payload in enumerate(llm_findings, 1):
            # parse driver name safely out of the standard payload prefix '--- WORK_ID (driver.sys) ---'
            first_line = payload.split('\n')[0]
            work_id = "unknown_work"
            dname = "unknown_driver.sys"
            import re
            m = re.search(r'---\s*(.*?)\s*\((.*?)\)\s*---', first_line)
            if m:
                work_id = m.group(1).strip()
                dname = m.group(2).strip()

            # skip if a report already exists for this work_id
            report_dir = config.work_dir / work_id
            if (report_dir / "VULNERABLE_report.md").exists() or (report_dir / "SAFE_report.md").exists():
                console.print(f"[dim][{idx}/{len(llm_findings)}] {dname} — report exists, skipping[/]")
                continue
                
            prompt = (
                f"You are an expert vulnerability researcher specializing in Windows kernel driver exploitation. "
                f"Analyze the following decompiled code for driver: {dname}.\n\n"

                "CRITICAL ANALYSIS RULES — read these before you begin:\n\n"

                "1. PROVE USER CONTROLLABILITY: for every value that reaches a dangerous sink "
                "(memcpy size, MmMapIoSpace address, pointer dereference target), you MUST trace it back "
                "to the IOCTL input buffer (SystemBuffer at param_2+0x18, or UserBuffer at param_2+0x60). "
                "if the value comes from the device extension (param_1+0x28 or similar), a global variable, "
                "or a hardware register (READ_REGISTER_UCHAR, in()/out()), it is NOT user-controlled unless "
                "you can show a separate IOCTL that lets the user SET that value.\n\n"

                "2. REJECT THESE FALSE POSITIVE PATTERNS:\n"
                "   - internal driver buffer writes: if a pointer at device_extension+0xNN is written to, "
                "but the pointer itself was allocated by the driver (ExAllocatePool, MmAllocatePagesForMdl, "
                "IoAllocateMdl) and never set by user input, this is NOT an arbitrary write\n"
                "   - HID feature report buffers: drivers like ASUS, Synaptics, etc. write command bytes "
                "into their own HID report buffers — two user bytes going into a driver-allocated buffer "
                "is normal HID protocol, not a vulnerability\n"
                "   - hardware-gated code paths: if the dangerous operation is behind a check on MMIO "
                "registers (READ_REGISTER_UCHAR), SMI results (out(port, val) return values), or "
                "device_extension fields that are only set during PnP device start (EvtDeviceAdd), "
                "then the vulnerability requires physical hardware and is NOT exploitable without it\n"
                "   - PnP-dependent devices: if the device name contains a format specifier (%d, %s) "
                "or the symbolic_link is empty/partial, the device object only exists when hardware is "
                "enumerated — mark SAFE\n"
                "   - Ghidra decompilation artifacts: 'unaff_ESI', 'unaff_EDI' etc. are registers that "
                "Ghidra could not resolve — they are NOT user-controlled inputs, they are typically "
                "return values from hardware (SMI handlers, CPUID, etc.)\n"
                "   - speculative/assumed state: do NOT assume device extension fields have convenient "
                "initial values. if the exploit depends on 'assuming the initial state is X', it is "
                "speculative and must be marked SAFE\n\n"

                "3. EXPLOITABILITY REQUIREMENTS: a valid vulnerability MUST satisfy ALL of these:\n"
                "   a) the device can be opened from usermode (\\\\DosDevices\\\\Name exists unconditionally)\n"
                "   b) a specific IOCTL code is identified that routes to the vulnerable handler\n"
                "   c) the dangerous operation uses a value derived from the IOCTL input buffer\n"
                "   d) no hardware, firmware, or PnP initialization is required to reach the code path\n\n"

                "OUTPUT FORMAT:\n"
                "- the very first line MUST be either [VULNERABLE] or [SAFE]\n"
                "- if SAFE, briefly explain which false positive pattern applies\n"
                "- if VULNERABLE, include:\n"
                "  1. the exact IOCTL code\n"
                "  2. root cause trace showing data flow from input buffer to dangerous sink\n"
                "  3. PoC strategy with pseudo-code\n\n"
                f"Payload:\n{payload}"
            )
            
            console.print(f"[dim][{idx}/{len(llm_findings)}] Deep scanning [{work_id}] {dname}...[/]")
            try:
                result = agent.invoke({
                    "messages": [{"role": "user", "content": prompt}]
                })
                response = _extract_response(result)
                
                prefix = "SAFE" if "[safe]" in response.lower()[:50] else "VULNERABLE"
                
                report_dir.mkdir(parents=True, exist_ok=True)
                report_path = report_dir / f"{prefix}_report.md"
                report_path.write_text(response, encoding="utf-8")
                console.print(f"[bold green]Report saved:[/] {report_path}")

                # success — decay backoff toward minimum
                backoff_seconds = max(2.0, backoff_seconds * 0.7)
            except Exception as e:
                err_str = str(e)

                # rate limit hit — increase backoff
                if "429" in err_str or "quota" in err_str.lower() or "rate" in err_str.lower():
                    backoff_seconds = min(60.0, backoff_seconds * 2.0)
                    console.print(f"[bold yellow]Rate limited on {dname}, backoff now {backoff_seconds:.0f}s[/]")

                elif "400" in err_str and "token count" in err_str.lower():
                    console.print(f"[bold yellow]Token limit exceeded for {dname}. Dynamic truncation active...[/]")
                    payload_idx = prompt.rfind("Payload:\n")
                    if payload_idx != -1:
                        header = prompt[:payload_idx]
                        raw_payload = prompt[payload_idx:]
                        
                        max_fallback_chars = 750000 
                        if len(raw_payload) > max_fallback_chars:
                            truncated_payload = raw_payload[:max_fallback_chars] + f"\n... [truncated: {len(raw_payload)} -> {max_fallback_chars} chars]"
                            fallback_prompt = header + truncated_payload
                            
                            try:
                                console.print(f"[dim]Retrying {dname} with sliced context...[/]")
                                time.sleep(5)
                                result = agent.invoke({
                                    "messages": [{"role": "user", "content": fallback_prompt}]
                                })
                                response = _extract_response(result)
                                prefix = "SAFE" if "[safe]" in response.lower()[:50] else "VULNERABLE"
                                report_dir.mkdir(parents=True, exist_ok=True)
                                report_path = report_dir / f"{prefix}_report.md"
                                report_path.write_text(response, encoding="utf-8")
                                console.print(f"[bold green]Fallback report saved:[/] {report_path}")
                            except Exception as e2:
                                console.print(f"[bold red]Fallback failed for [{work_id}] {dname}:[/] {e2}")
                        else:
                             console.print(f"[bold red]LLM failed for [{work_id}] {dname} (payload not reducible):[/] {e}")
                else:
                    console.print(f"[bold red]LLM failed for [{work_id}] {dname}:[/] {e}")
                
            time.sleep(backoff_seconds)


if __name__ == "__main__":
    main()
