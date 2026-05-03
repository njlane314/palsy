from __future__ import annotations

import hashlib
import json
from datetime import timedelta

import pytest

from palsy.lockfiles import parse_lockfile
from palsy.models import (
    Decision,
    Ecosystem,
    Environment,
    LockfileAssessmentRequest,
    Permit,
    PermitSubject,
    PolicyDecision,
    ResolvedArtifact,
    ScanCapabilities,
    ScanReport,
    UniversalAssessmentRequest,
    UniversalAssessmentResponse,
)
from palsy.service import FirewallService
from palsy.settings import Settings
from palsy.utils import utcnow


def test_parse_requirements_txt_pinned_dependencies():
    request = LockfileAssessmentRequest(
        project="demo",
        lockfile_name="requirements-prod.txt",
        content="""
        # generated lockfile
        Requests==2.32.3 --hash=sha256:abc
        idna==3.10 ; python_version >= "3.11"
        """,
    )

    coordinates = parse_lockfile(request)

    assert [(coord.ecosystem, coord.name, coord.version) for coord in coordinates] == [
        (Ecosystem.pypi, "requests", "2.32.3"),
        (Ecosystem.pypi, "idna", "3.10"),
    ]


def test_parse_requirements_txt_rejects_unpinned_dependencies():
    request = LockfileAssessmentRequest(
        project="demo",
        lockfile_name="requirements.txt",
        content="requests>=2\n",
    )

    with pytest.raises(ValueError, match="must pin"):
        parse_lockfile(request)


def test_parse_requirements_txt_rejects_editable_dependencies():
    request = LockfileAssessmentRequest(
        project="demo",
        lockfile_name="requirements.txt",
        content="-e git+https://example.invalid/repo.git#egg=demo\n",
    )

    with pytest.raises(ValueError, match="unsupported pip option"):
        parse_lockfile(request)


def test_parse_package_lock_json_handles_scoped_packages():
    request = LockfileAssessmentRequest(
        project="demo",
        lockfile_name="package-lock.json",
        content=json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "demo"},
                    "node_modules/is-number": {"version": "7.0.0"},
                    "node_modules/@scope/tool": {"version": "1.2.3"},
                    "node_modules/a/node_modules/is-number": {"version": "7.0.0"},
                },
            }
        ),
    )

    coordinates = parse_lockfile(request)

    assert [(coord.ecosystem, coord.name, coord.version) for coord in coordinates] == [
        (Ecosystem.npm, "is-number", "7.0.0"),
        (Ecosystem.npm, "@scope/tool", "1.2.3"),
    ]


@pytest.mark.asyncio
async def test_lockfile_assessment_issues_build_permit_when_all_dependencies_allowed(
    monkeypatch,
    tmp_path,
):
    service = FirewallService(
        Settings(
            state_dir=tmp_path / "state",
            require_api_token=False,
            policy_file=None,
        )
    )

    async def fake_assess_universal(request: UniversalAssessmentRequest) -> UniversalAssessmentResponse:
        return _universal_response(request, Decision.allow)

    monkeypatch.setattr(service, "assess_universal", fake_assess_universal)

    response = await service.assess_lockfile(
        LockfileAssessmentRequest(
            project="demo",
            lockfile_name="requirements.txt",
            content="idna==3.10\npackaging==24.2\n",
            environment=Environment.ci,
        )
    )

    assert response.decision == Decision.allow
    assert response.permit is not None
    assert response.permit.subject.dependency_count == 2
    assert [dep.coordinate.name for dep in response.permit.subject.dependencies] == ["idna", "packaging"]
    assert service.signer.verify_build_permit(response.permit)


@pytest.mark.asyncio
async def test_lockfile_assessment_holds_build_permit_when_dependency_needs_review(
    monkeypatch,
    tmp_path,
):
    service = FirewallService(
        Settings(
            state_dir=tmp_path / "state",
            require_api_token=False,
            policy_file=None,
        )
    )

    async def fake_assess_universal(request: UniversalAssessmentRequest) -> UniversalAssessmentResponse:
        decision = Decision.review if request.coordinate.name == "needs-review" else Decision.allow
        return _universal_response(request, decision)

    monkeypatch.setattr(service, "assess_universal", fake_assess_universal)

    response = await service.assess_lockfile(
        LockfileAssessmentRequest(
            project="demo",
            lockfile_name="package-lock.json",
            content=json.dumps(
                {
                    "packages": {
                        "node_modules/clean": {"version": "1.0.0"},
                        "node_modules/needs-review": {"version": "2.0.0"},
                    }
                }
            ),
            environment=Environment.ci,
        )
    )

    assert response.decision == Decision.review
    assert response.permit is None
    assert response.reasons == ["1 dependency artefact requires review"]


def _universal_response(
    request: UniversalAssessmentRequest,
    decision: Decision,
) -> UniversalAssessmentResponse:
    name = request.coordinate.name or request.coordinate.project or "unnamed"
    version = request.coordinate.version or "0"
    digest = hashlib.sha256(f"{request.coordinate.ecosystem.value}:{name}:{version}".encode()).hexdigest()
    filename = f"{name.replace('/', '-')}-{version}.tgz"
    scan = ScanReport(
        ecosystem=request.coordinate.ecosystem,
        artifact_digest=digest,
        artifact_filename=filename,
        capabilities=ScanCapabilities(),
    )
    permit = None
    if decision == Decision.allow:
        permit = Permit(
            subject=PermitSubject(
                ecosystem=request.coordinate.ecosystem,
                project=name,
                name=name,
                version=version,
                filename=filename,
                digest=digest,
            ),
            decision=Decision.allow,
            environment=request.environment,
            policy_name="test",
            policy_hash="b" * 64,
            expires_at=utcnow() + timedelta(days=1),
            capabilities=ScanCapabilities(),
        )
    return UniversalAssessmentResponse(
        coordinate=request.coordinate,
        resolved=ResolvedArtifact(
            coordinate=request.coordinate,
            filename=filename,
            url=f"https://example.invalid/{filename}",
        ),
        digest=digest,
        storage_path=None,
        scan=scan,
        policy=PolicyDecision(
            decision=decision,
            reasons=["all configured checks passed"] if decision == Decision.allow else ["manual review required"],
            policy_name="test",
            policy_hash="b" * 64,
        ),
        permit=permit,
    )
