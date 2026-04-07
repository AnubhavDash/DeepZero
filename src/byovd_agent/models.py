from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# --- enums ---

class VulnClass(str, Enum):
    PHYSICAL_MEMORY_RW = "Physical Memory R/W"
    ARBITRARY_KERNEL_RW = "Arbitrary Kernel Memory R/W"
    PROCESS_MANIPULATION = "Process Manipulation"
    MSR_PORT_IO = "MSR / Port I/O Access"
    CALLBACK_REMOVAL = "Callback / Notification Removal"
    TOKEN_PRIVILEGE = "Token / Privilege Manipulation"
    UNSIGNED_DRIVER_LOAD = "Unsigned Driver Loading"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class BufferMethod(str, Enum):
    BUFFERED = "METHOD_BUFFERED"
    IN_DIRECT = "METHOD_IN_DIRECT"
    OUT_DIRECT = "METHOD_OUT_DIRECT"
    NEITHER = "METHOD_NEITHER"


# --- phase 1: triage ---

class TriageResult(BaseModel):
    path: str
    filename: str
    sha256: str = ""
    md5: str = ""
    imphash: str = ""
    size_bytes: int = 0
    machine_type: str = ""
    subsystem: str = ""
    is_kernel_driver: bool = False
    is_signed: bool = False
    signer: str = ""
    has_ioctl_surface: bool = False
    creates_device: bool = False
    creates_symlink: bool = False
    imported_dlls: list[str] = Field(default_factory=list)
    imported_functions: list[str] = Field(default_factory=list)
    dangerous_imports: list[str] = Field(default_factory=list)
    detected_vuln_classes: list[VulnClass] = Field(default_factory=list)
    vuln_class_confidence: dict[str, float] = Field(default_factory=dict)
    priority_score: float = 0.0
    is_known_vuln: bool = False
    reject_reason: str = ""
    passed_triage: bool = False


# --- phase 2: translation ---

class IOCTLCode(BaseModel):
    raw_code: int
    hex_code: str = ""
    device_type: int = 0
    function: int = 0
    method: BufferMethod = BufferMethod.BUFFERED
    access: int = 0

    def decode(self) -> None:
        self.hex_code = f"0x{self.raw_code:08X}"
        self.device_type = (self.raw_code >> 16) & 0xFFFF
        self.function = (self.raw_code >> 2) & 0xFFF
        self.method = BufferMethod(["METHOD_BUFFERED", "METHOD_IN_DIRECT",
                                     "METHOD_OUT_DIRECT", "METHOD_NEITHER"]
                                    [self.raw_code & 0x3])
        self.access = (self.raw_code >> 14) & 0x3


class DecompiledHandler(BaseModel):
    ioctl_code: IOCTLCode
    decompiled_c: str = ""
    called_apis: list[str] = Field(default_factory=list)
    accesses_user_buffer: bool = False
    buffer_method: BufferMethod = BufferMethod.BUFFERED


class TranslationResult(BaseModel):
    sha256: str
    driver_entry_c: str = ""
    dispatch_function_name: str = ""
    dispatch_function_c: str = ""
    device_name: str = ""
    symbolic_link: str = ""
    ioctl_handlers: list[DecompiledHandler] = Field(default_factory=list)
    function_count: int = 0
    analysis_log: str = ""
    success: bool = False
    error: str = ""


# --- phase 3: identification ---

class SemgrepFinding(BaseModel):
    rule_id: str
    severity: Severity = Severity.MEDIUM
    message: str = ""
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    matched_code: str = ""
    ioctl_code: str = ""


class VulnAssessment(BaseModel):
    finding_id: str
    severity: Severity = Severity.MEDIUM
    vuln_class: VulnClass = VulnClass.ARBITRARY_KERNEL_RW
    title: str = ""
    description: str = ""
    root_cause: str = ""
    ioctl_code: str = ""
    affected_handler: str = ""
    user_reachable: bool = False
    requires_admin: bool = True
    exploit_primitive: str = ""
    confidence: float = 0.0
    evidence: dict[str, Any] = Field(default_factory=dict)
    semgrep_hits: list[str] = Field(default_factory=list)
    llm_reasoning: str = ""


class DriverAnalysis(BaseModel):
    """top-level result for a single driver through the full pipeline"""
    triage: TriageResult
    translation: TranslationResult | None = None
    semgrep_findings: list[SemgrepFinding] = Field(default_factory=list)
    vuln_assessments: list[VulnAssessment] = Field(default_factory=list)
    overall_risk: Severity = Severity.INFO
    executive_summary: str = ""
