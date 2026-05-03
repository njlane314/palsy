from __future__ import annotations

from pathlib import Path

import httpx

from ..models import ArtifactCoordinate, DownloadResult, Ecosystem, ResolvedArtifact
from ..utils import normalize_pypi_name, parse_datetime
from .base import ProviderError, download_http_file, verify_expected_digests


class PyPIProvider:
    ecosystem = Ecosystem.pypi
    mirrorable = True

    def __init__(self, upstream: str, *, timeout_seconds: float, allow_http: bool = False):
        self.upstream = upstream.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.allow_http = allow_http

    async def resolve(self, coordinate: ArtifactCoordinate) -> ResolvedArtifact:
        name = normalize_pypi_name(coordinate.name)
        version = coordinate.version
        if not version:
            raise ProviderError("PyPI coordinate requires version")
        url = f"{self.upstream}/pypi/{name}/{version}/json"
        async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=True) as client:
            resp = await client.get(url)
        if resp.status_code == 404:
            raise ProviderError(f"PyPI package/version not found: {name}=={version}")
        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ProviderError(f"PyPI metadata fetch failed: {exc.response.status_code}") from exc
        data = resp.json()
        files = data.get("urls") or []
        if not files:
            raise ProviderError(f"PyPI release has no downloadable files: {name}=={version}")
        if coordinate.filename:
            selected = next((item for item in files if item.get("filename") == coordinate.filename), None)
            if not selected:
                raise ProviderError(f"file {coordinate.filename!r} not found in PyPI release")
        else:
            wheels = [item for item in files if item.get("packagetype") == "bdist_wheel"]
            selected = sorted(wheels or files, key=lambda item: (item.get("filename") or ""))[0]
        filename = selected.get("filename")
        file_url = selected.get("url")
        if not filename or not file_url:
            raise ProviderError("PyPI file metadata is missing filename or URL")
        digests = {k.lower(): v for k, v in (selected.get("digests") or {}).items() if v}
        return ResolvedArtifact(
            coordinate=ArtifactCoordinate(ecosystem=Ecosystem.pypi, name=name, version=version, filename=filename),
            filename=filename,
            url=file_url,
            media_type=selected.get("packagetype"),
            size=selected.get("size"),
            published_at=parse_datetime(selected.get("upload_time_iso_8601") or selected.get("upload_time")),
            expected_digests=digests,
            metadata={
                "source": "pypi-json",
                "project_info": data.get("info", {}),
                "python_version": selected.get("python_version"),
                "yanked": selected.get("yanked"),
                "requires_python": selected.get("requires_python"),
            },
        )

    async def download(self, resolved: ResolvedArtifact, destination: Path, max_bytes: int) -> DownloadResult:
        if not resolved.url:
            raise ProviderError("resolved PyPI artefact has no URL")
        result = await download_http_file(
            resolved.url,
            destination,
            max_bytes=max_bytes,
            timeout_seconds=self.timeout_seconds,
            allow_http=self.allow_http,
        )
        result.verified_digests = verify_expected_digests(destination, resolved.expected_digests)
        return result
