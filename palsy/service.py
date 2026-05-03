from __future__ import annotations

import json
import logging
from datetime import timedelta
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from .db import Database
from .lockfiles import parse_lockfile
from .mirror import MirrorStore
from .models import (
    ArtifactCoordinate,
    ArtifactStatus,
    AssessmentRequest,
    AssessmentResponse,
    BuildPermit,
    BuildPermitDependency,
    BuildPermitSubject,
    Decision,
    Environment,
    LockfileAssessmentRequest,
    LockfileAssessmentResponse,
    LockfileDependencyResult,
    Permit,
    PermitSubject,
    ResolvedArtifact,
    ReviewApproval,
    ReviewApprovalRequest,
    ReviewApprovalResponse,
    ReviewItem,
    RevokeResponse,
    UniversalAssessmentRequest,
    UniversalAssessmentResponse,
)
from .permits import PermitSigner
from .policy import PolicyConfig, PolicyContext, PolicyEngine
from .providers import ProviderRegistry
from .providers.base import ProviderError
from .pypi_client import PyPIClient
from .scanner import StaticArtifactScanner
from .settings import Settings
from .sandbox import run_sandbox_if_enabled
from .utils import normalize_project_name, sha256_bytes, sha256_file, utcnow

logger = logging.getLogger(__name__)


class FirewallService:
    def __init__(self, settings: Settings):
        settings.ensure_dirs()
        self.settings = settings
        self.db = Database(settings.db_path)
        self.mirror = MirrorStore(settings.mirror_dir, settings.quarantine_dir)
        self.pypi = PyPIClient(
            settings.upstream_pypi,
            timeout_seconds=settings.http_timeout_seconds,
            allow_http=settings.allow_insecure_upstream_http,
        )
        self.providers = ProviderRegistry(settings)
        self.scanner = StaticArtifactScanner()
        self.policy_config = PolicyConfig.load(settings.policy_file)
        self.policy = PolicyEngine(self.policy_config)
        self.signer = PermitSigner(settings.key_path)

    async def assess(self, request: AssessmentRequest) -> AssessmentResponse:
        coord = ArtifactCoordinate(project=request.project, version=request.version, filename=request.filename)
        file = await self.pypi.resolve_file(coord)
        quarantine_path = self.mirror.quarantine_path(coord.project, coord.version, file.filename)

        digest: str
        if quarantine_path.exists():
            digest = sha256_file(quarantine_path)
            if file.sha256 and digest.lower() != file.sha256.lower():
                quarantine_path.unlink(missing_ok=True)
                digest = await self.pypi.download(file, quarantine_path, self.settings.max_artifact_bytes)
        else:
            digest = await self.pypi.download(file, quarantine_path, self.settings.max_artifact_bytes)

        self.db.upsert_artifact(
            ecosystem="pypi",
            project=coord.project,
            version=coord.version,
            filename=file.filename,
            digest=digest,
            url=file.url,
            size=file.size,
            upload_time=file.upload_time_iso_8601.isoformat() if file.upload_time_iso_8601 else None,
            status=ArtifactStatus.quarantined,
            storage_path=str(quarantine_path),
        )

        scan = None if request.force_rescan else self.db.latest_scan(digest)
        if scan is None:
            scan = self.scanner.scan(quarantine_path, digest=digest)
            self.db.save_scan(scan)

        should_sandbox = request.sandbox or (
            request.environment == Environment.prod and self.policy_config.require_sandbox_for_prod
        )
        sandbox = None
        if should_sandbox:
            sandbox = await run_sandbox_if_enabled(
                self.settings.sandbox_backend,
                quarantine_path,
                scan.top_level_modules,
                timeout_seconds=self.settings.sandbox_timeout_seconds,
            )

        previous_scan = self._previous_allowed_scan(coord.project, coord.version)
        policy_result = self.policy.evaluate(
            PolicyContext(
                project=coord.project,
                version=coord.version,
                environment=request.environment,
                file=file,
                scan=scan,
                sandbox=sandbox,
                previous_scan=previous_scan,
                revoked=self.db.is_revoked(digest),
            )
        )
        self.db.save_decision(
            artifact_digest=digest,
            environment=request.environment.value,
            decision=policy_result.decision,
            policy_name=policy_result.policy_name,
            policy_hash=policy_result.policy_hash,
            reasons=policy_result.reasons,
        )
        self._log_policy_decision(
            project=coord.project,
            version=coord.version,
            filename=file.filename,
            digest=digest,
            environment=request.environment,
            decision=policy_result.decision,
            reasons=policy_result.reasons,
            policy_name=policy_result.policy_name,
            policy_hash=policy_result.policy_hash,
        )

        storage_path: Path | None = None
        permit: Permit | None = None
        if policy_result.decision == Decision.allow:
            storage_path = self.mirror.promote(quarantine_path, coord.project, coord.version, digest, file.filename)
            self.db.upsert_artifact(
                ecosystem="pypi",
                project=coord.project,
                version=coord.version,
                filename=file.filename,
                digest=digest,
                url=file.url,
                size=file.size,
                upload_time=file.upload_time_iso_8601.isoformat() if file.upload_time_iso_8601 else None,
                status=ArtifactStatus.allowed,
                storage_path=str(storage_path),
            )
            permit = Permit(
                subject=PermitSubject(
                    project=coord.project,
                    version=coord.version,
                    filename=file.filename,
                    digest=digest,
                ),
                decision=policy_result.decision,
                environment=request.environment,
                policy_name=policy_result.policy_name,
                policy_hash=policy_result.policy_hash,
                expires_at=utcnow() + timedelta(seconds=self.policy_config.permit_ttl_seconds),
                capabilities=scan.capabilities,
                findings=scan.findings,
                reasons=policy_result.reasons,
            )
            permit = self.signer.sign(permit)
            self.db.save_permit(permit)
        elif policy_result.decision == Decision.review:
            self.db.set_artifact_status(digest, ArtifactStatus.review)
        else:
            self.db.set_artifact_status(digest, ArtifactStatus.denied)

        return AssessmentResponse(
            coordinate=coord,
            file=file,
            digest=digest,
            storage_path=str(storage_path) if storage_path else None,
            scan=scan,
            sandbox=sandbox,
            policy=policy_result,
            permit=permit,
        )

    async def assess_universal(self, request: UniversalAssessmentRequest) -> UniversalAssessmentResponse:
        provider = self.providers.get(request.coordinate.ecosystem)
        resolved = await provider.resolve(request.coordinate)
        quarantine_path = self.mirror.quarantine_path_for_resolved(resolved)
        download = await provider.download(resolved, quarantine_path, self.settings.max_artifact_bytes)
        digest = download.digest

        self.db.upsert_resolved_artifact(
            digest=digest,
            resolved=resolved,
            status=ArtifactStatus.quarantined,
            storage_path=download.path,
            size=download.size,
        )

        scan = None if request.force_rescan else self.db.latest_scan(digest)
        if scan is None:
            scan = self.scanner.scan(Path(download.path), resolved=resolved, digest=digest)
            if download.verified_digests:
                scan.metadata["verified_digests"] = download.verified_digests
            self.db.save_scan(scan)

        should_sandbox = request.sandbox or (
            request.environment == Environment.prod
            and self.policy_config.require_sandbox_for_prod
            and resolved.coordinate.ecosystem.value in {"pypi", "npm"}
        )
        sandbox = None
        if should_sandbox:
            sandbox = await run_sandbox_if_enabled(
                self.settings.sandbox_backend,
                Path(download.path),
                scan.top_level_modules,
                timeout_seconds=self.settings.sandbox_timeout_seconds,
            )

        previous_scan = self._previous_allowed_scan_universal(resolved)
        policy_result = self.policy.evaluate(
            PolicyContext(
                project=resolved.coordinate.name or resolved.coordinate.project or "unnamed",
                version=resolved.coordinate.version,
                ecosystem=resolved.coordinate.ecosystem,
                environment=request.environment,
                resolved=resolved,
                scan=scan,
                sandbox=sandbox,
                previous_scan=previous_scan,
                revoked=self.db.is_revoked(digest),
            )
        )
        self.db.save_decision(
            artifact_digest=digest,
            environment=request.environment.value,
            decision=policy_result.decision,
            policy_name=policy_result.policy_name,
            policy_hash=policy_result.policy_hash,
            reasons=policy_result.reasons,
        )
        self._log_policy_decision(
            project=resolved.coordinate.name or resolved.coordinate.project or "unnamed",
            version=resolved.coordinate.version or "unversioned",
            filename=resolved.filename,
            digest=digest,
            environment=request.environment,
            decision=policy_result.decision,
            reasons=policy_result.reasons,
            policy_name=policy_result.policy_name,
            policy_hash=policy_result.policy_hash,
        )

        storage_path: Path | None = None
        permit: Permit | None = None
        if policy_result.decision == Decision.allow:
            storage_path = self.mirror.promote_universal(Path(download.path), digest, resolved.filename)
            self.db.upsert_resolved_artifact(
                digest=digest,
                resolved=resolved,
                status=ArtifactStatus.allowed,
                storage_path=str(storage_path),
                size=download.size,
            )
            permit = self._issue_permit_for_resolved(
                resolved,
                digest,
                request.environment,
                scan,
                policy_result.reasons,
            )
        elif policy_result.decision == Decision.review:
            self.db.set_artifact_status(digest, ArtifactStatus.review)
        else:
            self.db.set_artifact_status(digest, ArtifactStatus.denied)

        return UniversalAssessmentResponse(
            coordinate=resolved.coordinate,
            resolved=resolved,
            digest=digest,
            storage_path=str(storage_path) if storage_path else None,
            scan=scan,
            sandbox=sandbox,
            policy=policy_result,
            permit=permit,
        )

    async def assess_lockfile(self, request: LockfileAssessmentRequest) -> LockfileAssessmentResponse:
        lockfile_digest = sha256_bytes(request.content.encode("utf-8"))
        coordinates = parse_lockfile(request)
        items: list[LockfileDependencyResult] = []
        for coordinate in coordinates:
            try:
                response = await self.assess_universal(
                    UniversalAssessmentRequest(
                        coordinate=coordinate,
                        environment=request.environment,
                        sandbox=request.sandbox,
                        force_rescan=request.force_rescan,
                    )
                )
            except (ProviderError, ValueError) as exc:
                items.append(
                    LockfileDependencyResult(
                        coordinate=coordinate,
                        decision=Decision.deny,
                        reasons=[f"dependency resolution failed: {exc}"],
                    )
                )
                continue

            items.append(
                LockfileDependencyResult(
                    coordinate=response.coordinate,
                    digest=response.digest,
                    filename=response.resolved.filename,
                    decision=response.policy.decision,
                    reasons=response.policy.reasons,
                    permit_id=response.permit.id if response.permit else None,
                    max_severity=response.scan.max_severity,
                    finding_count=len(response.scan.findings),
                    capabilities=response.scan.capabilities,
                    findings=response.scan.findings,
                    top_level_modules=response.scan.top_level_modules,
                    file_count=response.scan.file_count,
                    total_uncompressed_size=response.scan.total_uncompressed_size,
                    metadata=response.scan.metadata,
                    resolved_url=response.resolved.url,
                    published_at=response.resolved.published_at,
                    media_type=response.resolved.media_type,
                    mutable_reference=response.resolved.mutable_reference,
                )
            )

        decision, reasons = self._lockfile_decision(items)
        permit: BuildPermit | None = None
        if decision == Decision.allow:
            dependencies = [
                BuildPermitDependency(
                    coordinate=item.coordinate,
                    digest=item.digest,
                    permit_id=item.permit_id,
                )
                for item in items
                if item.digest
            ]
            permit = BuildPermit(
                subject=BuildPermitSubject(
                    project=request.project,
                    lockfile_name=request.lockfile_name,
                    lockfile_digest=lockfile_digest,
                    dependency_count=len(items),
                    artifact_digests=[dependency.digest for dependency in dependencies],
                    dependencies=dependencies,
                ),
                environment=request.environment,
                policy_name=self.policy_config.name,
                policy_hash=self.policy_config.hash,
                expires_at=utcnow() + timedelta(seconds=self.policy_config.permit_ttl_seconds),
                reasons=reasons,
            )
            permit = self.signer.sign_build_permit(permit)

        return LockfileAssessmentResponse(
            project=request.project,
            environment=request.environment,
            lockfile_name=request.lockfile_name,
            lockfile_digest=lockfile_digest,
            dependency_count=len(items),
            decision=decision,
            reasons=reasons,
            policy_name=self.policy_config.name,
            policy_hash=self.policy_config.hash,
            items=items,
            permit=permit,
        )

    def permit_by_id(self, permit_id: str) -> Permit | None:
        permit = self.db.get_permit(permit_id)
        if permit and self.signer.verify(permit):
            return permit
        return None

    def permit_for_digest(self, digest: str, environment: str | None = None) -> Permit | None:
        permit = self.db.latest_valid_permit(digest, environment)
        if permit and self.signer.verify(permit):
            return permit
        return None

    def revoke(self, digest: str, reason: str, actor: str) -> RevokeResponse:
        self.db.revoke(digest, reason, actor)
        return RevokeResponse(digest=digest, revoked=True, reason=reason, actor=actor, revoked_at=utcnow())

    def provider_infos(self):
        return self.providers.infos()

    def review_queue(self, limit: int = 100) -> list[ReviewItem]:
        items: list[ReviewItem] = []
        for row in self.db.review_artifacts(limit=max(1, min(limit, 500))):
            scan = self.db.latest_scan(row["digest"])
            decision = self.db.latest_decision(row["digest"])
            reasons: list[str] = []
            environment: Environment | None = None
            policy_name: str | None = None
            policy_hash: str | None = None
            if decision:
                reasons = json.loads(decision["reasons_json"])
                environment = Environment(decision["environment"])
                policy_name = decision["policy_name"]
                policy_hash = decision["policy_hash"]
            items.append(
                ReviewItem(
                    digest=row["digest"],
                    project=row["project"],
                    version=row["version"],
                    filename=row["filename"],
                    status=ArtifactStatus(row["status"]),
                    environment=environment,
                    max_severity=scan.max_severity if scan else None,
                    finding_count=len(scan.findings) if scan else 0,
                    reasons=reasons,
                    policy_name=policy_name,
                    policy_hash=policy_hash,
                    updated_at=row["updated_at"],
                )
            )
        return items

    def approve_review(self, digest: str, request: ReviewApprovalRequest) -> ReviewApprovalResponse:
        artifact = self.db.get_artifact(digest)
        if not artifact:
            raise ValueError("artefact not found")
        if artifact["status"] != ArtifactStatus.review.value:
            raise ValueError("artefact is not waiting for review")
        if self.db.is_revoked(digest):
            raise ValueError("revoked artefacts cannot be approved")

        scan = self.db.latest_scan(digest)
        if scan is None:
            raise ValueError("reviewed artefact has no scan report")

        source = Path(artifact["storage_path"])
        if not source.is_file():
            raise ValueError("quarantined artefact content is unavailable")

        approval = ReviewApproval(
            digest=digest,
            environment=request.environment,
            reviewer=request.reviewer,
            reason=request.reason,
            policy_name=self.policy_config.name,
            policy_hash=self.policy_config.hash,
        )
        storage_path = (
            self.mirror.promote(source, artifact["project"], artifact["version"], digest, artifact["filename"])
            if artifact["ecosystem"] == "pypi"
            else self.mirror.promote_universal(source, digest, artifact["filename"])
        )
        self.db.upsert_artifact(
            ecosystem=artifact["ecosystem"],
            project=artifact["project"],
            version=artifact["version"],
            filename=artifact["filename"],
            digest=digest,
            url=artifact["url"],
            size=artifact["size"],
            upload_time=artifact["upload_time"],
            status=ArtifactStatus.allowed,
            storage_path=str(storage_path),
        )
        self.db.save_review_approval(approval)

        permit = Permit(
            subject=PermitSubject(
                ecosystem=artifact["ecosystem"],
                project=artifact["project"],
                name=artifact["project"],
                version=artifact["version"],
                filename=artifact["filename"],
                digest=digest,
                media_type=artifact.get("media_type"),
            ),
            decision=Decision.allow,
            environment=request.environment,
            policy_name=approval.policy_name,
            policy_hash=approval.policy_hash,
            expires_at=utcnow() + timedelta(seconds=self.policy_config.permit_ttl_seconds),
            capabilities=scan.capabilities,
            findings=scan.findings,
            reasons=[f"manual approval by {request.reviewer}: {request.reason}"],
        )
        permit = self.signer.sign(permit)
        self.db.save_permit(permit)
        self.db.save_decision(
            artifact_digest=digest,
            environment=request.environment.value,
            decision=Decision.allow,
            policy_name=approval.policy_name,
            policy_hash=approval.policy_hash,
            reasons=permit.reasons,
        )
        self._log_policy_decision(
            project=artifact["project"],
            version=artifact["version"],
            filename=artifact["filename"],
            digest=digest,
            environment=request.environment,
            decision=Decision.allow,
            reasons=permit.reasons,
            policy_name=approval.policy_name,
            policy_hash=approval.policy_hash,
        )
        return ReviewApprovalResponse(approval=approval, permit=permit)

    def simple_index(self, project: str) -> str:
        normalized = normalize_project_name(project)
        rows = self.db.allowed_files_for_ecosystem_project("pypi", normalized)
        return self.mirror.simple_index_html(normalized, rows)

    def npm_packument(self, package: str, base_url: str = "") -> dict[str, Any]:
        name = package.strip().lower()
        rows = self.db.allowed_files_for_ecosystem_project("npm", name)
        return self.mirror.npm_packument(name, rows, base_url=base_url)

    def file_by_digest(self, digest: str, filename: str) -> Path | None:
        artifact = self.db.get_artifact(digest)
        if artifact and artifact.get("status") == ArtifactStatus.allowed.value:
            path = artifact.get("storage_path")
            if path and Path(path).is_file() and Path(path).name == filename:
                return Path(path)
        return self.mirror.file_by_digest(digest, filename)

    def blast_radius(self, digest: str) -> dict[str, Any]:
        return self.db.affected_by_digest(digest)

    def _previous_allowed_scan(self, project: str, version: str):
        current = self._parse_version(version)
        if current is None:
            return None
        candidates = []
        for row in self.db.artifacts_for_project(project, ArtifactStatus.allowed):
            candidate_version = self._parse_version(row["version"])
            if candidate_version is not None and candidate_version < current:
                candidates.append((candidate_version, row["digest"]))
        if not candidates:
            return None
        _, digest = sorted(candidates, key=lambda item: item[0])[-1]
        return self.db.latest_scan(digest)

    def _previous_allowed_scan_universal(self, resolved: ResolvedArtifact):
        current = self._parse_version(resolved.coordinate.version)
        if current is None:
            return None
        candidates = []
        name = resolved.coordinate.name or resolved.coordinate.project or "unnamed"
        for row in self.db.artifacts_for_package(
            resolved.coordinate.ecosystem.value,
            name,
            ArtifactStatus.allowed,
        ):
            candidate_version = self._parse_version(row["version"])
            if candidate_version is not None and candidate_version < current:
                candidates.append((candidate_version, row["digest"]))
        if not candidates:
            return None
        _, digest = sorted(candidates, key=lambda item: item[0])[-1]
        return self.db.latest_scan(digest)

    def _parse_version(self, version: str) -> Version | None:
        if not version:
            return None
        try:
            return Version(version)
        except InvalidVersion:
            return None

    def _issue_permit_for_resolved(
        self,
        resolved: ResolvedArtifact,
        digest: str,
        environment: Environment,
        scan,
        reasons: list[str],
    ) -> Permit:
        permit = Permit(
            subject=PermitSubject(
                ecosystem=resolved.coordinate.ecosystem,
                project=resolved.coordinate.name or resolved.coordinate.project,
                name=resolved.coordinate.name or resolved.coordinate.project,
                version=resolved.coordinate.version,
                filename=resolved.filename,
                digest=digest,
                media_type=resolved.media_type,
                metadata={
                    "url": resolved.url,
                    "mutable_reference": resolved.mutable_reference,
                    "package_metadata": resolved.metadata,
                },
            ),
            decision=Decision.allow,
            environment=environment,
            policy_name=self.policy_config.name,
            policy_hash=self.policy_config.hash,
            expires_at=utcnow() + timedelta(seconds=self.policy_config.permit_ttl_seconds),
            capabilities=scan.capabilities,
            findings=scan.findings,
            reasons=reasons,
        )
        permit = self.signer.sign(permit)
        self.db.save_permit(permit)
        return permit

    def _lockfile_decision(self, items: list[LockfileDependencyResult]) -> tuple[Decision, list[str]]:
        denied = [item for item in items if item.decision == Decision.deny]
        review = [item for item in items if item.decision == Decision.review]
        if denied:
            reasons = [
                self._count_reason(
                    len(denied),
                    "dependency artefact denied",
                    "dependency artefacts denied",
                )
            ]
            if review:
                reasons.append(
                    self._count_reason(
                        len(review),
                        "dependency artefact requires review",
                        "dependency artefacts require review",
                    )
                )
            return Decision.deny, reasons
        if review:
            return (
                Decision.review,
                [
                    self._count_reason(
                        len(review),
                        "dependency artefact requires review",
                        "dependency artefacts require review",
                    )
                ],
            )
        return Decision.allow, [
            self._count_reason(
                len(items),
                "dependency artefact passed policy",
                "dependency artefacts passed policy",
            )
        ]

    def _count_reason(self, count: int, singular: str, plural: str) -> str:
        noun = singular if count == 1 else plural
        return f"{count} {noun}"

    def _log_policy_decision(
        self,
        *,
        project: str,
        version: str,
        filename: str,
        digest: str,
        environment: Environment,
        decision: Decision,
        reasons: list[str],
        policy_name: str,
        policy_hash: str,
    ) -> None:
        logger.info(
            "policy decision project=%s version=%s filename=%s digest=%s environment=%s "
            "decision=%s policy=%s policy_hash=%s reasons=%s",
            project,
            version,
            filename,
            digest,
            environment.value,
            decision.value,
            policy_name,
            policy_hash,
            json.dumps(reasons, sort_keys=True),
        )
