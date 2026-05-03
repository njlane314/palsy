from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from ..models import ArtifactCoordinate, DownloadResult, Ecosystem, ResolvedArtifact
from .base import ProviderError, download_http_file, expected_digest_from_coordinate, verify_expected_digests


class GenericURLProvider:
    ecosystem = Ecosystem.generic
    mirrorable = False

    def __init__(self, *, timeout_seconds: float, allow_http: bool = False):
        self.upstream = None
        self.timeout_seconds = timeout_seconds
        self.allow_http = allow_http

    async def resolve(self, coordinate: ArtifactCoordinate) -> ResolvedArtifact:
        url = coordinate.url or coordinate.name
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ProviderError("generic provider supports only HTTP(S) URLs")
        filename = coordinate.filename or Path(parsed.path).name or "artefact.bin"
        return ResolvedArtifact(
            coordinate=ArtifactCoordinate(
                ecosystem=Ecosystem.generic,
                name=coordinate.name,
                version=coordinate.version or coordinate.expected_digest or "unversioned",
                filename=filename,
                url=url,
                expected_digest=coordinate.expected_digest,
            ),
            filename=filename,
            url=url,
            media_type=None,
            expected_digests=expected_digest_from_coordinate(coordinate),
            mutable_reference=not bool(coordinate.expected_digest),
            metadata={"source": "generic-url"},
        )

    async def download(self, resolved: ResolvedArtifact, destination: Path, max_bytes: int) -> DownloadResult:
        if not resolved.url:
            raise ProviderError("generic artefact has no URL")
        result = await download_http_file(
            resolved.url,
            destination,
            max_bytes=max_bytes,
            timeout_seconds=self.timeout_seconds,
            allow_http=self.allow_http,
        )
        result.verified_digests = verify_expected_digests(destination, resolved.expected_digests)
        return result
