from __future__ import annotations

import json
import tarfile
from pathlib import Path

import pytest

from palsy.models import ArtifactCoordinate, DownloadResult, Ecosystem, ResolvedArtifact, UniversalAssessmentRequest
import palsy.providers.generic as generic_provider
from palsy.providers.registry import ProviderRegistry
from palsy.scanner import StaticArtifactScanner
from palsy.service import FirewallService
from palsy.settings import Settings


def test_provider_registry_contains_multiple_ecosystems(tmp_path):
    registry = ProviderRegistry(Settings(state_dir=tmp_path))
    ecosystems = {info.ecosystem for info in registry.infos()}
    assert {Ecosystem.pypi, Ecosystem.npm, Ecosystem.oci, Ecosystem.generic}.issubset(ecosystems)


def test_npm_lifecycle_script_detected(tmp_path: Path):
    tgz = tmp_path / "pkg-1.0.0.tgz"
    package_json = json.dumps(
        {"name": "pkg", "version": "1.0.0", "scripts": {"postinstall": "node install.js"}}
    ).encode()
    payload = tmp_path / "package.json"
    payload.write_bytes(package_json)
    with tarfile.open(tgz, "w:gz") as tf:
        tf.add(payload, arcname="package/package.json")
    resolved = ResolvedArtifact(
        coordinate=ArtifactCoordinate(ecosystem=Ecosystem.npm, name="pkg", version="1.0.0"),
        filename=tgz.name,
        url="https://example.invalid/pkg.tgz",
    )

    report = StaticArtifactScanner().scan(tgz, resolved=resolved, digest="e" * 64)

    assert report.ecosystem == Ecosystem.npm
    assert report.capabilities.contains_npm_package is True
    assert report.capabilities.has_lifecycle_scripts is True
    assert any(f.rule_id == "npm.lifecycle_script" for f in report.findings)


@pytest.mark.asyncio
async def test_generic_assessment_with_expected_digest(monkeypatch, tmp_path):
    body = b"hello from a generic artefact\n"
    digest = __import__("hashlib").sha256(body).hexdigest()
    url = "https://downloads.example.test/tool.txt"

    async def fake_download(url, destination, *, max_bytes, timeout_seconds, allow_http, headers=None):
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(body)
        return DownloadResult(
            path=str(destination),
            digest=digest,
            size=len(body),
            verified_digests={"sha256": digest},
        )

    monkeypatch.setattr(generic_provider, "download_http_file", fake_download)
    service = FirewallService(
        Settings(
            state_dir=tmp_path / "state",
            require_api_token=False,
            policy_file=None,
        )
    )

    response = await service.assess_universal(
        UniversalAssessmentRequest(
            coordinate=ArtifactCoordinate(
                ecosystem=Ecosystem.generic,
                name=url,
                expected_digest=f"sha256:{digest}",
            )
        )
    )

    assert response.coordinate.ecosystem == Ecosystem.generic
    assert response.digest == digest
    assert response.policy.decision == "allow"
    assert response.permit is not None
    assert response.permit.subject.ecosystem == Ecosystem.generic
