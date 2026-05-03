from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Ecosystem(str, Enum):
    pypi = "pypi"
    npm = "npm"
    oci = "oci"
    generic = "generic"


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
    ecosystem: Ecosystem = Ecosystem.pypi
    project: str | None = Field(default=None, min_length=1, max_length=512)
    name: str | None = Field(default=None, min_length=1, max_length=512)
    version: str | None = Field(default=None, max_length=512)
    filename: str | None = Field(default=None, max_length=512)
    url: str | None = Field(default=None, max_length=4096)
    expected_digest: str | None = Field(default=None, max_length=256)
    platform: str | None = Field(default=None, max_length=128)

    @field_validator("project", "name")
    @classmethod
    def clean_name(cls, value: str | None) -> str | None:
        return value.strip() if value else value

    @model_validator(mode="after")
    def validate_shape(self) -> "ArtifactCoordinate":
        if not self.name and self.project:
            self.name = self.project
        if not self.project and self.name:
            self.project = self.name
        if self.ecosystem == Ecosystem.pypi:
            if self.project:
                self.project = self.project.strip().replace("_", "-").lower()
                self.name = self.project
            if not self.version:
                raise ValueError("PyPI coordinates require version")
        elif self.ecosystem in {Ecosystem.npm, Ecosystem.oci}:
            if not self.name:
                raise ValueError(f"{self.ecosystem.value} coordinates require name")
            if not self.version:
                raise ValueError(f"{self.ecosystem.value} coordinates require version/ref")
        elif self.ecosystem == Ecosystem.generic:
            if not self.url and not (self.name and self.name.startswith(("http://", "https://"))):
                raise ValueError("generic coordinates require url or a URL-valued name")
            if not self.name:
                self.name = self.url
                self.project = self.url
        return self


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
    contains_archive: bool = False
    contains_wheel: bool = False
    contains_sdist: bool = False
    contains_npm_package: bool = False
    contains_oci_manifest: bool = False
    generic_unidentified: bool = False
    has_pth_exec: bool = False
    has_startup_hook: bool = False
    has_install_hook: bool = False
    has_lifecycle_scripts: bool = False
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
    npm_integrity_verified: bool = False
    oci_runs_as_root: bool = False
    oci_has_secret_env: bool = False
    oci_has_shell_entrypoint: bool = False
    oci_mutable_reference: bool = False

    def true_flags(self) -> set[str]:
        return {name for name, value in self.model_dump().items() if value is True}


class ScanReport(BaseModel):
    ecosystem: Ecosystem = Ecosystem.pypi
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


class ResolvedArtifact(BaseModel):
    coordinate: ArtifactCoordinate
    filename: str
    url: str | None = None
    media_type: str | None = None
    size: int | None = None
    published_at: datetime | None = None
    expected_digests: dict[str, str] = Field(default_factory=dict)
    integrity: str | None = None
    mutable_reference: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def expected_sha256(self) -> str | None:
        value = self.expected_digests.get("sha256")
        if value and value.startswith("sha256:"):
            return value.split(":", 1)[1]
        return value


class DownloadResult(BaseModel):
    path: str
    digest: str
    size: int
    verified_digests: dict[str, str] = Field(default_factory=dict)
    identity_digest_algorithm: str = "sha256"


class PermitSubject(BaseModel):
    ecosystem: Ecosystem = Ecosystem.pypi
    project: str | None = None
    name: str | None = None
    version: str | None
    filename: str
    digest: str
    media_type: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def set_names(self) -> "PermitSubject":
        if not self.name and self.project:
            self.name = self.project
        if not self.project and self.name:
            self.project = self.name
        return self


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


class BuildPermitDependency(BaseModel):
    coordinate: ArtifactCoordinate
    digest: str
    permit_id: str | None = None


class BuildPermitSubject(BaseModel):
    project: str = Field(min_length=1, max_length=512)
    lockfile_name: str = Field(min_length=1, max_length=512)
    lockfile_digest: str = Field(min_length=64, max_length=128)
    dependency_count: int = Field(ge=0)
    artifact_digests: list[str] = Field(default_factory=list)
    dependencies: list[BuildPermitDependency] = Field(default_factory=list)


class BuildPermit(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    subject: BuildPermitSubject
    decision: Decision = Decision.allow
    environment: Environment
    policy_name: str
    policy_hash: str
    issued_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime
    reasons: list[str] = Field(default_factory=list)
    signature: str | None = None
    public_key: str | None = None


class AssessmentRequest(BaseModel):
    project: str
    version: str
    filename: str | None = None
    environment: Environment = Environment.ci
    sandbox: bool = False
    force_rescan: bool = False


class UniversalAssessmentRequest(BaseModel):
    coordinate: ArtifactCoordinate
    environment: Environment = Environment.ci
    sandbox: bool = False
    force_rescan: bool = False


class LockfileAssessmentRequest(BaseModel):
    project: str = Field(min_length=1, max_length=512)
    lockfile_name: str = Field(min_length=1, max_length=512)
    content: str = Field(min_length=1, max_length=5_000_000)
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


class UniversalAssessmentResponse(BaseModel):
    coordinate: ArtifactCoordinate
    resolved: ResolvedArtifact
    digest: str
    storage_path: str | None
    scan: ScanReport
    sandbox: SandboxReport | None = None
    policy: PolicyDecision
    permit: Permit | None = None


class LockfileDependencyResult(BaseModel):
    coordinate: ArtifactCoordinate
    digest: str | None = None
    filename: str | None = None
    decision: Decision
    reasons: list[str] = Field(default_factory=list)
    permit_id: str | None = None
    max_severity: Severity | None = None
    finding_count: int = 0
    capabilities: ScanCapabilities | None = None
    findings: list[Finding] = Field(default_factory=list)
    top_level_modules: list[str] = Field(default_factory=list)
    file_count: int = 0
    total_uncompressed_size: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)
    resolved_url: str | None = None
    published_at: datetime | None = None
    media_type: str | None = None
    mutable_reference: bool = False


class LockfileAssessmentResponse(BaseModel):
    project: str
    environment: Environment
    lockfile_name: str
    lockfile_digest: str
    dependency_count: int
    decision: Decision
    reasons: list[str] = Field(default_factory=list)
    policy_name: str
    policy_hash: str
    items: list[LockfileDependencyResult] = Field(default_factory=list)
    permit: BuildPermit | None = None


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


class ProviderInfo(BaseModel):
    ecosystem: Ecosystem
    upstream: str | None
    mirrorable: bool = False
    notes: str | None = None
