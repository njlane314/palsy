from __future__ import annotations

from datetime import datetime, timedelta, timezone

from palsy.models import Environment, PyPIFile
from palsy.policy import PolicyConfig, PolicyContext, PolicyEngine
from palsy.scanner import StaticArtifactScanner

from .test_helpers import write_wheel


def test_policy_denies_pth_exec(tmp_path):
    wheel = write_wheel(
        tmp_path / "demo-1.0.0-py3-none-any.whl",
        files={"demo_hook.pth": b"import os\n"},
    )
    scan = StaticArtifactScanner().scan(wheel)
    file = PyPIFile(
        filename=wheel.name,
        url="https://files.pythonhosted.org/packages/demo.whl",
        packagetype="bdist_wheel",
        upload_time_iso_8601=datetime.now(timezone.utc) - timedelta(days=10),
        digests={"sha256": scan.artifact_digest},
    )
    policy = PolicyEngine(PolicyConfig(minimum_release_age_seconds={"default": 0}))
    result = policy.evaluate(
        PolicyContext(project="demo", version="1.0.0", environment=Environment.ci, file=file, scan=scan)
    )
    assert result.decision == "deny"
    assert any(".pth" in reason for reason in result.reasons)


def test_policy_quarantines_fresh_prod_release(tmp_path):
    wheel = write_wheel(tmp_path / "demo-1.0.0-py3-none-any.whl")
    scan = StaticArtifactScanner().scan(wheel)
    file = PyPIFile(
        filename=wheel.name,
        url="https://files.pythonhosted.org/packages/demo.whl",
        packagetype="bdist_wheel",
        upload_time_iso_8601=datetime.now(timezone.utc),
        digests={"sha256": scan.artifact_digest},
    )
    policy = PolicyEngine(PolicyConfig(minimum_release_age_seconds={"prod": 86400}, require_sandbox_for_prod=False))
    result = policy.evaluate(
        PolicyContext(project="demo", version="1.0.0", environment=Environment.prod, file=file, scan=scan)
    )
    assert result.decision == "deny"
    assert any("release age" in reason for reason in result.reasons)
