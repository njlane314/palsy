from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.info: 0,
    Severity.low: 1,
    Severity.medium: 2,
    Severity.high: 3,
    Severity.critical: 4,
}


class Decision(str, Enum):
    allow = "allow"
    review = "review"
    deny = "deny"


class Environment(str, Enum):
    dev = "dev"
    ci = "ci"
    prod = "prod"


class ArtifactStatus(str, Enum):
    quarantined = "quarantined"
    allowed = "allowed"
    review = "review"
    denied = "denied"
    revoked = "revoked"


class ArtifactCoordinate(BaseModel):
    ecosystem: Literal["pypi"] = "pypi"
    project: str = Field(min_length=1, max_length=256)
    version: str = Field(min_length=1, max_length=256)
    filename: str | None = Field(default=None, max_length=512)

    @field_validator("project")
    @classmethod
    def normalize_project(cls, value: str) -> str:
        # PEP 503 normalization is hyphen-based and lowercase. We keep the user's
        # display value elsewhere; this coordinate is for stable lookup.
        return value.strip().replace("_", "-").lower()


class PyPIFile(BaseModel):
    filename: str
    url: str
    packagetype: str
    python_version: str | None = None
    size: int | None = None
    upload_time_iso_8601: datetime | None = None
    digests: dict[str, str] = Field(default_factory=dict)
    yanked: bool | str | None = None

    @property
    def sha256(self) -> str | None:
        return self.digests.get("sha256")


class Finding(BaseModel):
    rule_id: str
    severity: Severity
    title: str
    description: str
    location: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)


class ScanCapabilities(BaseModel):
    contains_wheel: bool = False
    contains_sdist: bool = False
    has_pth_exec: bool = False
    has_startup_hook: bool = False
    has_install_hook: bool = False
    has_native_code: bool = False
    has_hidden_runtime: bool = False
    has_embedded_interpreter: bool = False
    has_large_obfuscated_blob: bool = False
    references_credentials: bool = False
    references_network: bool = False
    imports_subprocess: bool = False
    imports_socket: bool = False
    import_time_sensitive: bool = False
    record_validated: bool = False
    record_missing: bool = False
    path_traversal: bool = False


class ScanReport(BaseModel):
    artifact_digest: str
    artifact_filename: str
    scanned_at: datetime = Field(default_factory=utcnow)
    capabilities: ScanCapabilities = Field(default_factory=ScanCapabilities)
    findings: list[Finding] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    top_level_modules: list[str] = Field(default_factory=list)
    file_count: int = 0
    total_uncompressed_size: int = 0

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.info
        return max((f.severity for f in self.findings), key=lambda sev: SEVERITY_RANK[sev])


class DynamicEvent(BaseModel):
    kind: str
    detail: str
    severity: Severity = Severity.info
    evidence: dict[str, Any] = Field(default_factory=dict)


class SandboxReport(BaseModel):
    enabled: bool = False
    executed: bool = False
    success: bool = False
    timeout: bool = False
    events: list[DynamicEvent] = Field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    duration_ms: int | None = None


class PolicyDecision(BaseModel):
    decision: Decision
    reasons: list[str] = Field(default_factory=list)
    policy_name: str
    policy_hash: str
    evaluated_at: datetime = Field(default_factory=utcnow)


class PermitSubject(BaseModel):
    ecosystem: Literal["pypi"] = "pypi"
    project: str
    version: str
    filename: str
    digest: str


class Permit(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    subject: PermitSubject
    decision: Decision
    environment: Environment
    policy_name: str
    policy_hash: str
    issued_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime
    capabilities: ScanCapabilities
    findings: list[Finding] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    revoked: bool = False
    signature: str | None = None
    public_key: str | None = None


class AssessmentRequest(BaseModel):
    project: str
    version: str
    filename: str | None = None
    environment: Environment = Environment.ci
    sandbox: bool = False
    force_rescan: bool = False


class AssessmentResponse(BaseModel):
    coordinate: ArtifactCoordinate
    file: PyPIFile
    digest: str
    storage_path: str | None
    scan: ScanReport
    sandbox: SandboxReport | None = None
    policy: PolicyDecision
    permit: Permit | None = None


class RevokeRequest(BaseModel):
    digest: str = Field(min_length=64, max_length=128)
    reason: str = Field(min_length=1, max_length=1000)
    actor: str = Field(default="api", max_length=256)


class RevokeResponse(BaseModel):
    digest: str
    revoked: bool
    reason: str
    actor: str
    revoked_at: datetime


class ReviewItem(BaseModel):
    digest: str
    project: str
    version: str
    filename: str
    status: ArtifactStatus
    environment: Environment | None = None
    max_severity: Severity | None = None
    finding_count: int = 0
    reasons: list[str] = Field(default_factory=list)
    policy_name: str | None = None
    policy_hash: str | None = None
    updated_at: datetime


class ReviewApprovalRequest(BaseModel):
    environment: Environment = Environment.ci
    reviewer: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=1, max_length=1000)


class ReviewApproval(BaseModel):
    digest: str
    environment: Environment
    reviewer: str
    reason: str
    policy_name: str
    policy_hash: str
    approved_at: datetime = Field(default_factory=utcnow)


class ReviewApprovalResponse(BaseModel):
    approval: ReviewApproval
    permit: Permit
