from __future__ import annotations

import json
import logging
from datetime import timedelta
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from .db import Database
from .mirror import MirrorStore
from .models import (
    ArtifactCoordinate,
    ArtifactStatus,
    AssessmentRequest,
    AssessmentResponse,
    Decision,
    Environment,
    Permit,
    PermitSubject,
    ReviewApproval,
    ReviewApprovalRequest,
    ReviewApprovalResponse,
    ReviewItem,
    RevokeResponse,
)
from .permits import PermitSigner
from .policy import PolicyConfig, PolicyContext, PolicyEngine
from .pypi_client import PyPIClient
from .scanner import StaticArtifactScanner
from .settings import Settings
from .sandbox import run_sandbox_if_enabled
from .utils import normalize_project_name, sha256_file, utcnow

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
        storage_path = self.mirror.promote(
            source,
            artifact["project"],
            artifact["version"],
            digest,
            artifact["filename"],
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
                project=artifact["project"],
                version=artifact["version"],
                filename=artifact["filename"],
                digest=digest,
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
        rows = self.db.allowed_files_for_project(normalized)
        return self.mirror.simple_index_html(normalized, rows)

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

    def _parse_version(self, version: str) -> Version | None:
        try:
            return Version(version)
        except InvalidVersion:
            return None

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
