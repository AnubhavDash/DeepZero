from __future__ import annotations

from byovd_agent.models import VulnClass

# maps each vulnerability class to the ntoskrnl imports that indicate it
VULN_CLASS_IMPORTS: dict[VulnClass, list[str]] = {
    VulnClass.PHYSICAL_MEMORY_RW: [
        "MmMapIoSpace", "MmUnmapIoSpace",
        "ZwMapViewOfSection", "ZwUnmapViewOfSection",
        "ZwOpenSection", "MmGetPhysicalAddress",
        "MmMapLockedPagesSpecifyCache", "MmMapLockedPages",
        "HalTranslateBusAddress", "MmAllocateContiguousMemory",
    ],
    VulnClass.ARBITRARY_KERNEL_RW: [
        "MmProbeAndLockPages", "MmUnlockPages",
        "IoAllocateMdl", "IoFreeMdl",
        "MmBuildMdlForNonPagedPool", "MmIsAddressValid",
        "MmGetSystemRoutineAddress", "MmCopyVirtualMemory",
        "MmCopyMemory",
    ],
    VulnClass.PROCESS_MANIPULATION: [
        "PsLookupProcessByProcessId", "ObOpenObjectByPointer",
        "ZwOpenProcess", "ZwTerminateProcess",
        "PsGetProcessImageFileName", "PsGetProcessId",
        "KeStackAttachProcess", "KeUnstackDetachProcess",
    ],
    VulnClass.MSR_PORT_IO: [
        "__readmsr", "__writemsr",
        "HalGetBusDataByOffset", "HalSetBusDataByOffset",
        "READ_PORT_UCHAR", "WRITE_PORT_UCHAR",
        "READ_PORT_USHORT", "WRITE_PORT_USHORT",
        "READ_PORT_ULONG", "WRITE_PORT_ULONG",
    ],
    VulnClass.CALLBACK_REMOVAL: [
        "ObRegisterCallbacks", "ObUnRegisterCallbacks",
        "PsSetCreateProcessNotifyRoutine", "PsSetCreateProcessNotifyRoutineEx",
        "PsRemoveCreateThreadNotifyRoutine", "PsRemoveLoadImageNotifyRoutine",
        "CmRegisterCallbackEx", "CmUnRegisterCallback",
    ],
    VulnClass.TOKEN_PRIVILEGE: [
        "ZwOpenProcessTokenEx", "NtQueryInformationToken",
        "SeExports", "RtlCreateSecurityDescriptor",
        "RtlSetDaclSecurityDescriptor",
    ],
    VulnClass.UNSIGNED_DRIVER_LOAD: [
        "ZwLoadDriver", "ZwUnloadDriver",
        "MmLoadSystemImage", "MmUnloadSystemImage",
        "ZwSetSystemInformation",
    ],
}

# how many hits per class before we flag it
THRESHOLDS: dict[VulnClass, int] = {
    VulnClass.PHYSICAL_MEMORY_RW: 2,
    VulnClass.ARBITRARY_KERNEL_RW: 2,
    VulnClass.PROCESS_MANIPULATION: 2,
    VulnClass.MSR_PORT_IO: 1,
    VulnClass.CALLBACK_REMOVAL: 2,
    VulnClass.TOKEN_PRIVILEGE: 2,
    VulnClass.UNSIGNED_DRIVER_LOAD: 1,
}

# any single import from this set is enough to indicate the driver
# might expose a user-reachable attack surface. covers raw WDM,
# WDF/KMDF, PortCls, NDIS miniport, StorPort, and other frameworks
# that create device objects or handle IRPs on behalf of the minidriver
IOCTL_SURFACE_INDICATORS = {
    # wdm device creation
    "IoCreateDevice", "IoCreateDeviceSecure",
    # symbolic link creation
    "IoCreateSymbolicLink",
    # irp completion — any driver that completes IRPs handles requests
    "IofCompleteRequest", "IoCompleteRequest",
    # wdf/kmdf framework entry points
    "WdfDeviceCreate", "WdfDeviceCreateSymbolicLink",
    "WdfIoQueueCreate", "WdfRequestComplete",
    "WdfDriverCreate",
    # portcls audio miniport drivers
    "PcRegisterSubdevice", "PcDispatchIrp", "PcAddAdapterDevice",
    "PcRegisterAdapterPowerManagement",
    # ndis miniport/filter/protocol drivers
    "NdisMRegisterMiniportDriver", "NdisFRegisterFilterDriver",
    "NdisRegisterProtocolDriver", "NdisMRegisterIoPortRange",
    # storport/scsiport miniport drivers
    "StorPortInitialize", "ScsiPortInitialize",
    # class driver frameworks
    "HidRegisterMinidriver", "StreamClassRegisterMinidriver",
    "KsCreateFilterFactory",
    # direct ioctl dispatch setup
    "IoConnectInterrupt", "IoRegisterDeviceInterface",
}

# all the dangerous APIs flattened for quick membership checks
DANGEROUS_APIS: set[str] = set()
for funcs in VULN_CLASS_IMPORTS.values():
    DANGEROUS_APIS.update(funcs)


def classify_imports(imported_functions: list[str]) -> dict[VulnClass, float]:
    """given a flat list of imported function names, return detected
    vulnerability classes with confidence 0.0-1.0"""
    func_set = set(imported_functions)
    results: dict[VulnClass, float] = {}

    for vc, indicators in VULN_CLASS_IMPORTS.items():
        hits = func_set.intersection(indicators)
        if len(hits) >= THRESHOLDS[vc]:
            confidence = min(1.0, len(hits) / (len(indicators) * 0.5))
            results[vc] = round(confidence, 2)

    return results


def has_ioctl_surface(imported_functions: list[str]) -> bool:
    """check if the driver has any indicator of a user-reachable attack surface"""
    return bool(set(imported_functions) & IOCTL_SURFACE_INDICATORS)


def get_dangerous_hits(imported_functions: list[str]) -> list[str]:
    """return just the dangerous API names found in imports"""
    return sorted(set(imported_functions) & DANGEROUS_APIS)
