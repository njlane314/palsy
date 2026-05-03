from __future__ import annotations

from pathlib import Path
from urllib.parse import quote

import httpx

from ..models import ArtifactCoordinate, DownloadResult, Ecosystem, ResolvedArtifact
from ..utils import parse_datetime
from .base import ProviderError, download_http_file, verify_expected_digests, verify_sri


class NpmProvider:
    ecosystem = Ecosystem.npm
    mirrorable = True

    def __init__(self, upstream: str, *, timeout_seconds: float, allow_http: bool = False, token: str | None = None):
        self.upstream = upstream.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.allow_http = allow_http
        self.token = token

    async def resolve(self, coordinate: ArtifactCoordinate) -> ResolvedArtifact:
        name = coordinate.name.strip().lower()
        ref = coordinate.version or "latest"
        escaped = quote(name, safe="")
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=True) as client:
            resp = await client.get(f"{self.upstream}/{escaped}", headers=headers)
        if resp.status_code == 404:
            raise ProviderError(f"npm package not found: {name}")
        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ProviderError(f"npm metadata fetch failed: {exc.response.status_code}") from exc
        doc = resp.json()
        versions = doc.get("versions") or {}
        dist_tags = doc.get("dist-tags") or {}
        version = ref if ref in versions else dist_tags.get(ref)
        if not version or version not in versions:
            raise ProviderError(f"npm package ref not found: {name}@{ref}")
        manifest = versions[version]
        dist = manifest.get("dist") or {}
        tarball = dist.get("tarball")
        if not tarball:
            raise ProviderError(f"npm package has no tarball URL: {name}@{version}")
        filename = coordinate.filename or tarball.rsplit("/", 1)[-1] or f"{name.replace('/', '-')}-{version}.tgz"
        expected: dict[str, str] = {}
        if dist.get("shasum"):
            expected["sha1"] = dist["shasum"]
        return ResolvedArtifact(
            coordinate=ArtifactCoordinate(ecosystem=Ecosystem.npm, name=name, version=version, filename=filename),
            filename=filename,
            url=tarball,
            media_type="application/vnd.npm.tgz",
            size=dist.get("unpackedSize"),
            published_at=parse_datetime((doc.get("time") or {}).get(version)),
            expected_digests=expected,
            integrity=dist.get("integrity"),
            mutable_reference=(ref != version),
            metadata={
                "source": "npm-packument",
                "dist_tags": dist_tags,
                "scripts": manifest.get("scripts") or {},
                "dependencies": manifest.get("dependencies") or {},
                "optionalDependencies": manifest.get("optionalDependencies") or {},
                "devDependencies": manifest.get("devDependencies") or {},
                "maintainers": doc.get("maintainers") or [],
                "license": manifest.get("license"),
                "repository": manifest.get("repository"),
            },
        )

    async def download(self, resolved: ResolvedArtifact, destination: Path, max_bytes: int) -> DownloadResult:
        if not resolved.url:
            raise ProviderError("resolved npm artefact has no tarball URL")
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else None
        result = await download_http_file(
            resolved.url,
            destination,
            max_bytes=max_bytes,
            timeout_seconds=self.timeout_seconds,
            allow_http=self.allow_http,
            headers=headers,
        )
        verified = verify_sri(destination, resolved.integrity)
        verified.update(verify_expected_digests(destination, resolved.expected_digests))
        result.verified_digests = verified
        return result
