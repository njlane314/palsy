from __future__ import annotations

from palsy.models import ArtifactStatus, Environment, ReviewApprovalRequest
from palsy.scanner import StaticArtifactScanner
from palsy.service import FirewallService
from palsy.settings import Settings

from .test_helpers import write_wheel


def test_review_approval_promotes_artifact_and_records_reviewer(tmp_path):
    service = FirewallService(
        Settings(
            state_dir=tmp_path / "state",
            require_api_token=False,
        )
    )
    wheel = write_wheel(
        tmp_path / "demo-1.0.0-py3-none-any.whl",
        files={"demo/__init__.py": b"import subprocess\nsubprocess.Popen(['echo','x'])\n"},
    )
    scan = StaticArtifactScanner().scan(wheel)
    service.db.upsert_artifact(
        ecosystem="pypi",
        project="demo",
        version="1.0.0",
        filename=wheel.name,
        digest=scan.artifact_digest,
        url=None,
        size=wheel.stat().st_size,
        upload_time=None,
        status=ArtifactStatus.review,
        storage_path=str(wheel),
    )
    service.db.save_scan(scan)

    queue = service.review_queue()
    assert len(queue) == 1
    assert queue[0].digest == scan.artifact_digest
    assert queue[0].max_severity.value == "high"

    response = service.approve_review(
        scan.artifact_digest,
        ReviewApprovalRequest(
            environment=Environment.ci,
            reviewer="security",
            reason="Reviewed subprocess use in the demo package.",
        ),
    )

    artifact = service.db.get_artifact(scan.artifact_digest)
    assert artifact is not None
    assert artifact["status"] == ArtifactStatus.allowed.value
    assert response.approval.reviewer == "security"
    assert response.permit.signature
    assert service.permit_for_digest(scan.artifact_digest, Environment.ci.value) is not None
    blast_radius = service.blast_radius(scan.artifact_digest)
    assert blast_radius["review_approvals"][0]["reason"] == "Reviewed subprocess use in the demo package."
