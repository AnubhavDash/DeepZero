from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path

import pefile

from byovd_agent.knowledge.vuln_patterns import (
    classify_imports,
    get_dangerous_hits,
    has_ioctl_surface,
)
from byovd_agent.models import TriageResult, VulnClass

log = logging.getLogger(__name__)

TRIAGE_CACHE_FILE = "triage_results.json"


def _compute_hashes(data: bytes) -> tuple[str, str]:
    """return (sha256, md5) of raw bytes"""
    return hashlib.sha256(data).hexdigest(), hashlib.md5(data).hexdigest()


def _get_imphash(pe: pefile.PE) -> str:
    try:
        return pe.get_imphash() or ""
    except Exception:
        return ""


def _extract_imports(pe: pefile.PE) -> tuple[list[str], list[str]]:
    """return (dll_names, function_names) from PE import table"""
    dlls: list[str] = []
    funcs: list[str] = []
    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
    except Exception:
        return dlls, funcs

    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return dlls, funcs

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode("utf-8", errors="replace")
        dlls.append(dll)
        for imp in entry.imports:
            if imp.name:
                funcs.append(imp.name.decode("utf-8", errors="replace"))

    return dlls, funcs


def _check_signature(pe: pefile.PE) -> tuple[bool, str]:
    """basic check for authenticode signature presence"""
    try:
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        if sec_dir.VirtualAddress != 0 and sec_dir.Size != 0:
            return True, ""
    except (IndexError, AttributeError):
        pass
    return False, ""


def _compute_priority(
    dangerous_imports: list[str],
    vuln_classes: dict[VulnClass, float],
    has_surface: bool,
    section_count: int,
) -> float:
    """priority score 0-10, higher = more interesting to analyze"""
    score = 0.0

    if not has_surface:
        return 0.0

    phys_mem = {"MmMapIoSpace", "ZwMapViewOfSection", "ZwOpenSection", "MmGetPhysicalAddress"}
    proc_manip = {"PsLookupProcessByProcessId", "ZwTerminateProcess", "ZwOpenProcess"}
    msr_io = {"__readmsr", "__writemsr", "HalGetBusDataByOffset", "HalSetBusDataByOffset"}

    if set(dangerous_imports) & phys_mem:
        score += 3.0
    if set(dangerous_imports) & proc_manip:
        score += 2.0
    if set(dangerous_imports) & msr_io:
        score += 2.0

    score += min(2.0, len(vuln_classes) * 0.5)

    if section_count <= 6:
        score += 1.0

    return min(10.0, score)


def triage_driver(sys_path: Path) -> TriageResult:
    """analyze a single .sys file and decide if it's worth deeper analysis"""
    result = TriageResult(
        path=str(sys_path),
        filename=sys_path.name,
    )

    try:
        data = sys_path.read_bytes()
    except OSError as e:
        result.reject_reason = f"cannot read file: {e}"
        return result

    result.size_bytes = len(data)

    # fast_load skips expensive directory parsing (resources, relocations, debug, etc)
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError:
        result.reject_reason = "invalid PE format"
        return result

    # check subsystem before doing any expensive work
    subsys = pe.OPTIONAL_HEADER.Subsystem
    subsys_names = {1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI"}
    result.subsystem = subsys_names.get(subsys, str(subsys))
    result.is_kernel_driver = subsys == 1

    if not result.is_kernel_driver:
        result.reject_reason = f"not a kernel driver (subsystem={result.subsystem})"
        pe.close()
        return result

    machine_types = {0x14C: "I386", 0x8664: "AMD64", 0xAA64: "ARM64"}
    result.machine_type = machine_types.get(
        pe.FILE_HEADER.Machine, f"0x{pe.FILE_HEADER.Machine:04X}"
    )

    # only parse the import and security directories — everything we actually need
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
        ])
    except Exception:
        pass

    result.imported_dlls, result.imported_functions = _extract_imports(pe)
    result.imphash = _get_imphash(pe)

    result.creates_device = "IoCreateDevice" in result.imported_functions
    result.creates_symlink = "IoCreateSymbolicLink" in result.imported_functions
    result.has_ioctl_surface = has_ioctl_surface(result.imported_functions)

    if not result.has_ioctl_surface:
        result.reject_reason = "no user-reachable IOCTL surface"
        pe.close()
        return result

    # passed all filters — now compute hashes (deferred to avoid wasting
    # cycles on the thousands of drivers rejected above)
    result.sha256, result.md5 = _compute_hashes(data)
    result.is_signed, result.signer = _check_signature(pe)

    result.dangerous_imports = get_dangerous_hits(result.imported_functions)

    classification = classify_imports(result.imported_functions)
    result.detected_vuln_classes = list(classification.keys())
    result.vuln_class_confidence = {vc.value: conf for vc, conf in classification.items()}

    section_count = pe.FILE_HEADER.NumberOfSections
    result.priority_score = _compute_priority(
        result.dangerous_imports, classification,
        result.has_ioctl_surface, section_count,
    )

    # boost modern drivers that declare win10+ compatibility
    try:
        if pe.OPTIONAL_HEADER.MajorOperatingSystemVersion >= 10:
            result.priority_score += 3.0
    except Exception:
        pass

    result.passed_triage = True
    pe.close()
    return result


def save_triage_results(results: list[TriageResult], cache_path: Path) -> None:
    """persist triage results to JSON for resumption"""
    data = [r.model_dump() for r in results]
    cache_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    log.info("[triage] saved %d results to %s", len(results), cache_path)


def load_triage_results(cache_path: Path) -> list[TriageResult] | None:
    """load cached triage results if they exist"""
    if not cache_path.exists():
        return None
    try:
        raw = json.loads(cache_path.read_text(encoding="utf-8"))
        results = [TriageResult(**r) for r in raw]
        log.info("[triage] loaded %d cached results from %s", len(results), cache_path)
        return results
    except (json.JSONDecodeError, Exception) as e:
        log.warning("[triage] failed to load cache: %s — will re-triage", e)
        return None


def batch_triage(
    sys_files: list[Path],
    known_hashes: set[str] | None = None,
    cache_dir: Path | None = None,
) -> list[TriageResult]:
    """triage all .sys files, dedup against known vulns, sort by priority.

    if cache_dir is provided, results are saved to triage_results.json.
    on subsequent runs, the cache is loaded instead of re-processing."""

    # check for cached results
    if cache_dir:
        cache_path = cache_dir / TRIAGE_CACHE_FILE
        cached = load_triage_results(cache_path)
        if cached is not None:
            return cached
    else:
        cache_path = None

    import concurrent.futures
    import os

    total = len(sys_files)
    passed_count = 0
    rejected_count = 0
    start_time = time.time()

    max_workers = min(os.cpu_count() or 4, 8)
    log.info("[triage] starting parallel triage of %d .sys files (%d workers)", total, max_workers)

    results: list[TriageResult] = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
        future_to_idx = {executor.submit(triage_driver, p): i for i, p in enumerate(sys_files)}
        completed = 0
        for future in concurrent.futures.as_completed(future_to_idx):
            completed += 1
            try:
                tri = future.result()
            except Exception as exc:
                idx = future_to_idx[future]
                tri = TriageResult(
                    path=str(sys_files[idx]),
                    filename=sys_files[idx].name,
                    reject_reason=f"triage exception: {exc}",
                )

            if tri.passed_triage and known_hashes and tri.sha256 in known_hashes:
                tri.is_known_vuln = True
                tri.reject_reason = "already known in LOLDrivers database"
                tri.passed_triage = False

            if tri.passed_triage:
                passed_count += 1
            else:
                rejected_count += 1

            results.append(tri)

            if completed % 500 == 0 or completed == total:
                elapsed = time.time() - start_time
                rate = completed / elapsed if elapsed > 0 else 0
                eta = (total - completed) / rate if rate > 0 else 0
                log.info(
                    "[triage] %d/%d (%.0f%%) | passed=%d rejected=%d | "
                    "%.0f files/sec | ETA %.0fs",
                    completed, total, completed / total * 100,
                    passed_count, rejected_count,
                    rate, eta,
                )

    results.sort(key=lambda r: (-int(r.passed_triage), -r.priority_score))

    elapsed = time.time() - start_time
    log.info(
        "[triage] COMPLETE: %d total, %d passed, %d rejected in %.1fs (%.0f files/sec)",
        total, passed_count, rejected_count, elapsed, total / elapsed if elapsed else 0,
    )

    # log top candidates
    top = [r for r in results if r.passed_triage][:10]
    if top:
        log.info("[triage] top %d candidates:", len(top))
        for r in top:
            vulns = ", ".join(v.value for v in r.detected_vuln_classes)
            log.info(
                "[triage]   [%.1f] %s | %s | [%s]",
                r.priority_score, r.filename, r.machine_type, vulns,
            )

    # save to cache
    if cache_path:
        save_triage_results(results, cache_path)

    return results
