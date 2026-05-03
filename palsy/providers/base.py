from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import Protocol
from urllib.parse import urlparse

import httpx

from ..models import ArtifactCoordinate, DownloadResult, Ecosystem, ResolvedArtifact
from ..utils import digest_file, parse_digest, sha256_file


class ProviderError(RuntimeError):
    pass


class ArtifactProvider(Protocol):
    ecosystem: Ecosystem
    upstream: str | None
    mirrorable: bool

    async def resolve(self, coordinate: ArtifactCoordinate) -> ResolvedArtifact:
        ...

    async def download(self, resolved: ResolvedArtifact, destination: Path, max_bytes: int) -> DownloadResult:
        ...


def require_https_or_allowed(url: str, allow_http: bool) -> None:
    parsed = urlparse(url)
    if parsed.scheme == "http" and not allow_http:
        raise ProviderError(f"refusing insecure upstream URL: {url}")
    if parsed.scheme not in {"http", "https"}:
        raise ProviderError(f"unsupported URL scheme: {url}")


async def download_http_file(
    url: str,
    destination: Path,
    *,
    max_bytes: int,
    timeout_seconds: float,
    allow_http: bool,
    headers: dict[str, str] | None = None,
) -> DownloadResult:
    require_https_or_allowed(url, allow_http)
    destination.parent.mkdir(parents=True, exist_ok=True)
    tmp = destination.with_suffix(destination.suffix + ".tmp")
    size = 0
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=True) as client:
            async with client.stream("GET", url, headers=headers or {}) as resp:
                resp.raise_for_status()
                with tmp.open("wb") as f:
                    async for chunk in resp.aiter_bytes():
                        size += len(chunk)
                        if size > max_bytes:
                            raise ProviderError(f"artefact exceeds maximum size {max_bytes} bytes")
                        f.write(chunk)
        tmp.replace(destination)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)
    return DownloadResult(path=str(destination), digest=sha256_file(destination), size=size)


def verify_expected_digests(path: Path, expected: dict[str, str]) -> dict[str, str]:
    verified: dict[str, str] = {}
    for algorithm, expected_value in expected.items():
        algo = algorithm.lower()
        expected_norm = expected_value.lower()
        if expected_norm.startswith(f"{algo}:"):
            expected_norm = expected_norm.split(":", 1)[1]
        if algo not in hashlib.algorithms_available:
            continue
        actual = digest_file(path, algo)
        if actual.lower() != expected_norm:
            raise ProviderError(f"{algo} digest mismatch: expected {expected_norm}, got {actual}")
        verified[algo] = actual
    return verified


def verify_sri(path: Path, integrity: str | None) -> dict[str, str]:
    if not integrity:
        return {}
    candidates = []
    for item in integrity.split():
        if "-" not in item:
            continue
        algo, b64 = item.split("-", 1)
        if algo.lower() in hashlib.algorithms_available:
            candidates.append((algo.lower(), b64))
    if not candidates:
        return {}
    candidates.sort(key=lambda pair: hashlib.new(pair[0]).digest_size, reverse=True)
    verified: dict[str, str] = {}
    for algo, b64 in candidates:
        expected = base64.b64decode(b64)
        h = hashlib.new(algo)
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        if h.digest() != expected:
            raise ProviderError(f"{algo} SRI mismatch")
        verified[algo] = h.hexdigest()
        break
    return verified


def expected_digest_from_coordinate(coordinate: ArtifactCoordinate) -> dict[str, str]:
    parsed = parse_digest(coordinate.expected_digest)
    return {parsed[0]: parsed[1]} if parsed else {}
