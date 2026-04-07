---
description: perform vulnerablity research, and write a PoC if exploitable
---

# driver vulnerability analysis and PoC workflow

the user will provide one or more file references (VULNERABLE_report.md, dispatch_ioctl.c, or a work directory hash). for each one, perform the full analysis pipeline below. do not ask clarifying questions — just execute.

## phase 1: gather context

1. read the VULNERABLE_report.md (if provided)
2. read `decompiled/ghidra_result.json` in the same work directory — extract: `device_name`, `symbolic_link`, `dispatch_name`, `function_count`
3. read `decompiled/dispatch_ioctl.c` — this is the primary source of truth, not the report

## phase 2: independent vulnerability analysis

ignore the report's conclusions. perform your own analysis from the decompiled code:

### 2a: attack surface check
- does the device create a symbolic link accessible from usermode? (`\\DosDevices\\Name`)
- is the device name static (good) or dynamic with format specifiers like `%d` (PnP-dependent, likely unusable)?
- does the driver require hardware initialization (PnP start, MMIO base, interrupt object) before IOCTLs work?
- check for access control: does `IoCreateDevice` set `FILE_DEVICE_SECURE_OPEN`? is there any ACL check in the dispatch handler?

### 2b: trace every IOCTL handler
for each IOCTL code found in the dispatch switch:
- identify the buffer method (METHOD_BUFFERED uses `Irp->AssociatedIrp.SystemBuffer` at `param_2 + 0x18`; METHOD_NEITHER uses `Irp->UserBuffer` at `param_2 + 0x60` and raw stack pointers)
- trace what happens to the input buffer contents — where do they flow?
- identify all dangerous sinks:
  - **arbitrary read**: MmMapIoSpace, ZwMapViewOfSection of PhysicalMemory, memcpy from kernel to user buffer with user-controlled source/size
  - **arbitrary write**: memcpy/RtlCopyMemory to kernel address with user-controlled dest/size, direct pointer dereference writes where the pointer is user-controlled
  - **code execution**: __writemsr (especially IA32_LSTAR 0xC0000082), wbinvd, function pointer overwrites
  - **pool overflow**: ExAllocatePool with user-controlled size followed by memcpy with different (larger) size
  - **stack overflow**: memcpy into stack buffer with user-controlled size
  - **info leak**: IoStatus.Information set to user-controlled value, kernel addresses copied to output buffer
  - **DoS**: NULL pointer dereference, divide by zero, infinite loop from user input
  - **MSR/IO port access**: __readmsr/__writemsr, READ_PORT_UCHAR/WRITE_PORT_UCHAR with user-controlled port/value
  - **CR register access**: __readcr/__writecr with user-controlled values

### 2c: prove or disprove user controllability
for every candidate vulnerability, trace the tainted data backward:
- does the dangerous value originate from `SystemBuffer` (user input)? → exploitable
- does it come from the device extension, a global, or a hardware register? → NOT exploitable unless another IOCTL lets the user set it
- is it a Ghidra artifact like `unaff_ESI`, `in_EAX`? → NOT user-controlled, likely register state from hardware/calling convention
- does the code path require hardware state (MMIO base != NULL, interrupt object initialized, SMI return values)? → hardware-gated, not exploitable without the device


## phase 3: write c PoC and compile if exploitable

if a real vulnerability is confirmed:

1. create `poc_<drivername>.c` in the work directory
2. the PoC must be a complete, compilable C file (MSVC `cl.exe` compatible)
3. include:
   - device handle opening via `CreateFileA("\\\\.<symlink>")`
   - proper error handling on every API call
   - the exact IOCTL code and buffer layout
   - hex dump of output if it's a read/leak
   - clear console output explaining each step
4. compile using cl
5. for dangerous primitives (arbitrary write), make the PoC demonstrate the primitive safely:
   - for writes: write to a known safe kernel address or just demonstrate the IOCTL succeeds
   - for reads: dump the first N bytes of physical memory or kernel pool


DO NOT WRITE ANY ANALYSIS REPORTS. JUST WRITE THE POC. IF NOT VULNERABLE, SAY WHY ITS NOT VULNERABLE.