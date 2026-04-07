from __future__ import annotations

import logging
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

# sdio packs most likely to contain exploitable ioctl drivers
# focused on hardware categories that require direct hw access
# and ship their own kernel-mode .sys binaries
PRIORITY_PACKS = [
    # chipset drivers — MSR access, physical memory mapping, port I/O
    "DP_Chipset",
    # network adapters — NDIS miniport drivers with management IOCTLs
    "DP_LAN_Intel", "DP_LAN_Realtek", "DP_LAN_Others",
    # wifi — complex protocol stacks, lots of IOCTLs
    "DP_WLAN",
    # storage controllers — SCSI/NVMe miniport with admin IOCTLs
    "DP_MassStorage",
    # card readers — often poorly written, direct hw access
    "DP_CardReader",
    # bluetooth — complex drivers with user-mode IOCTLs
    "DP_wBluetooth",
    # touchpad/input — filter drivers with IOCTLs
    "DP_Touchpad",
    # biometric — fingerprint readers etc, custom IOCTLs
    "DP_Biometric",
    # usb host controllers — direct hardware IOCTLs
    "DP_xUSB",
    # vendor-specific utility drivers — often the worst offenders
    "DP_Vendor",
]



def scan_for_sys_files(directory: Path) -> list[Path]:
    """recursively find all .sys files in a directory"""
    if not directory.exists():
        return []
    return sorted(directory.rglob("*.sys"))


def scan_priority_packs(
    drivers_root: Path,
    priority_only: bool = True,
) -> list[Path]:
    """scan an already-extracted SDIO drivers directory for .sys files
    in priority pack subdirectories"""
    if not drivers_root.exists():
        log.warning("drivers directory does not exist: %s", drivers_root)
        return []

    subdirs = sorted(d for d in drivers_root.iterdir() if d.is_dir())

    if priority_only:
        subdirs = [
            d for d in subdirs
            if any(p.lower() in d.name.lower() for p in PRIORITY_PACKS)
        ]

    log.info("scanning %d pack directories in %s", len(subdirs), drivers_root)

    all_sys: list[Path] = []
    for pack_dir in subdirs:
        sys_files = list(pack_dir.rglob("*.sys"))
        log.info("  %s: %d .sys files", pack_dir.name, len(sys_files))
        all_sys.extend(sys_files)

    log.info("total .sys files found: %d", len(all_sys))
    return all_sys


