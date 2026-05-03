from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from .models import ArtifactCoordinate, PyPIFile
from .utils import parse_datetime, sha256_file


class PyPIClientError(RuntimeError):
    pass


class PyPIClient:
    def __init__(self, base_url: str, timeout_seconds: float = 30.0, allow_http: bool = False):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout_seconds
        self.allow_http = allow_http

    def _validate_url(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https" and not self.allow_http:
            raise PyPIClientError(f"refusing non-HTTPS artefact URL: {url}")

    async def get_release_files(self, coordinate: ArtifactCoordinate) -> list[PyPIFile]:
        url = f"{self.base_url}/pypi/{coordinate.project}/{coordinate.version}/json"
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            response = await client.get(url)
        if response.status_code == 404:
            raise PyPIClientError(f"PyPI release not found: {coordinate.project}=={coordinate.version}")
        response.raise_for_status()
        payload: dict[str, Any] = response.json()
        files: list[PyPIFile] = []
        for item in payload.get("urls", []):
            uploaded = item.get("upload_time_iso_8601") or item.get("upload_time")
            files.append(
                PyPIFile(
                    filename=item["filename"],
                    url=item["url"],
                    packagetype=item.get("packagetype", "unknown"),
                    python_version=item.get("python_version"),
                    size=item.get("size"),
                    upload_time_iso_8601=parse_datetime(uploaded),
                    digests=item.get("digests") or {},
                    yanked=item.get("yanked"),
                )
            )
        return files

    async def resolve_file(self, coordinate: ArtifactCoordinate) -> PyPIFile:
        files = await self.get_release_files(coordinate)
        if not files:
            raise PyPIClientError(f"no files found for {coordinate.project}=={coordinate.version}")
        if coordinate.filename:
            for file in files:
                if file.filename == coordinate.filename:
                    return file
            raise PyPIClientError(
                f"file {coordinate.filename!r} not present for {coordinate.project}=={coordinate.version}"
            )
        wheels = [f for f in files if f.filename.endswith(".whl") and f.packagetype == "bdist_wheel"]
        if wheels:
            # Prefer universal wheels when available; otherwise choose the smallest compatible-looking wheel
            wheels.sort(key=lambda f: ("none-any" not in f.filename, f.size or 2**63))
            return wheels[0]
        sdists = [f for f in files if f.packagetype == "sdist" or f.filename.endswith((".tar.gz", ".zip"))]
        if sdists:
            sdists.sort(key=lambda f: f.size or 2**63)
            return sdists[0]
        files.sort(key=lambda f: f.size or 2**63)
        return files[0]

    async def download(self, file: PyPIFile, destination: Path, max_bytes: int) -> str:
        self._validate_url(file.url)
        destination.parent.mkdir(parents=True, exist_ok=True)
        tmp = destination.with_suffix(destination.suffix + ".part")
        total = 0
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            async with client.stream("GET", file.url) as response:
                response.raise_for_status()
                with tmp.open("wb") as out:
                    async for chunk in response.aiter_bytes():
                        total += len(chunk)
                        if total > max_bytes:
                            tmp.unlink(missing_ok=True)
                            raise PyPIClientError(
                                f"artefact exceeds configured size limit {max_bytes} bytes"
                            )
                        out.write(chunk)
        digest = sha256_file(tmp)
        expected = file.sha256
        if expected and digest.lower() != expected.lower():
            tmp.unlink(missing_ok=True)
            raise PyPIClientError(
                f"sha256 mismatch for {file.filename}: expected {expected}, got {digest}"
            )
        tmp.replace(destination)
        return digest
