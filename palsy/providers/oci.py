from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

import httpx

from ..models import ArtifactCoordinate, DownloadResult, Ecosystem, ResolvedArtifact
from ..utils import sha256_bytes
from .base import ProviderError

OCI_ACCEPT = ",".join(
    [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    ]
)
INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}


@dataclass(frozen=True)
class OCIReference:
    registry: str
    repository: str
    reference: str
    display_registry: str


class OCIProvider:
    ecosystem = Ecosystem.oci
    mirrorable = False

    def __init__(
        self,
        *,
        timeout_seconds: float,
        allow_http: bool = False,
        username: str | None = None,
        password: str | None = None,
    ):
        self.upstream = "oci-registries"
        self.timeout_seconds = timeout_seconds
        self.allow_http = allow_http
        self.username = username
        self.password = password

    async def resolve(self, coordinate: ArtifactCoordinate) -> ResolvedArtifact:
        ref = self._parse_reference(coordinate)
        manifest_bytes, media_type, digest = await self._get_manifest(ref, ref.reference)
        manifest = json.loads(manifest_bytes)
        selected_platform = coordinate.platform or "linux/amd64"
        if media_type in INDEX_TYPES or manifest.get("mediaType") in INDEX_TYPES:
            child = self._select_manifest(manifest, selected_platform)
            child_digest = child.get("digest")
            if not child_digest:
                raise ProviderError("OCI image index entry lacks digest")
            manifest_bytes, media_type, digest = await self._get_manifest(ref, child_digest)
            manifest = json.loads(manifest_bytes)
        hex_digest = digest.split(":", 1)[1] if digest.startswith("sha256:") else digest
        mutable = not ref.reference.startswith("sha256:")
        filename = f"{ref.repository.replace('/', '_').replace(':', '_')}@sha256-{hex_digest[:24]}.oci.json"
        return ResolvedArtifact(
            coordinate=ArtifactCoordinate(
                ecosystem=Ecosystem.oci,
                name=f"{ref.display_registry}/{ref.repository}",
                version=ref.reference,
                filename=filename,
                platform=selected_platform,
            ),
            filename=filename,
            url=f"oci://{ref.display_registry}/{ref.repository}@sha256:{hex_digest}",
            media_type=media_type,
            size=len(manifest_bytes),
            published_at=None,
            expected_digests={"sha256": hex_digest},
            mutable_reference=mutable,
            metadata={
                "registry": ref.registry,
                "display_registry": ref.display_registry,
                "repository": ref.repository,
                "reference": ref.reference,
                "selected_platform": selected_platform,
                "manifest": manifest,
                "manifest_digest": f"sha256:{hex_digest}",
            },
        )

    async def download(self, resolved: ResolvedArtifact, destination: Path, max_bytes: int) -> DownloadResult:
        meta = resolved.metadata
        ref = OCIReference(
            registry=str(meta["registry"]),
            repository=str(meta["repository"]),
            reference=str(meta["reference"]),
            display_registry=str(meta.get("display_registry") or meta["registry"]),
        )
        manifest = meta.get("manifest") or {}
        config_descriptor = manifest.get("config") or {}
        config_blob: dict[str, Any] | None = None
        if config_descriptor.get("digest"):
            blob = await self._get_blob(ref, config_descriptor["digest"], max_bytes=min(max_bytes, 128 * 1024 * 1024))
            try:
                config_blob = json.loads(blob)
            except json.JSONDecodeError:
                config_blob = {"_raw_sha256": sha256_bytes(blob), "_size": len(blob)}
        bundle = {
            "kind": "palsy.oci.bundle.v1",
            "registry": ref.registry,
            "display_registry": ref.display_registry,
            "repository": ref.repository,
            "reference": ref.reference,
            "resolved_digest": meta.get("manifest_digest"),
            "media_type": resolved.media_type,
            "manifest": manifest,
            "config": config_blob,
        }
        data = json.dumps(bundle, sort_keys=True, indent=2).encode("utf-8")
        if len(data) > max_bytes:
            raise ProviderError("OCI metadata bundle exceeds maximum artefact size")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        expected = resolved.expected_sha256
        if not expected:
            raise ProviderError("OCI manifest has no resolved sha256 digest")
        return DownloadResult(
            path=str(destination),
            digest=expected,
            size=len(data),
            verified_digests={"sha256": expected},
            identity_digest_algorithm="oci-manifest-sha256",
        )

    def _parse_reference(self, coordinate: ArtifactCoordinate) -> OCIReference:
        raw = coordinate.name.strip()
        ref = coordinate.version or "latest"
        if "@" in raw:
            raw, embedded = raw.rsplit("@", 1)
            ref = embedded
        parts = raw.split("/")
        first = parts[0]
        if "." in first or ":" in first or first == "localhost":
            registry = first
            repository = "/".join(parts[1:])
            display_registry = registry
        else:
            registry = "registry-1.docker.io"
            display_registry = "docker.io"
            repository = raw if "/" in raw else f"library/{raw}"
        if not repository:
            raise ProviderError("OCI reference is missing repository")
        if not re.match(r"^[A-Za-z0-9_./:-]+$", repository):
            raise ProviderError(f"OCI repository contains invalid characters: {repository!r}")
        return OCIReference(registry=registry, repository=repository, reference=ref, display_registry=display_registry)

    async def _get_manifest(self, ref: OCIReference, reference: str) -> tuple[bytes, str, str]:
        path = f"/v2/{ref.repository}/manifests/{quote(reference, safe=':')}"
        headers = {"Accept": OCI_ACCEPT}
        resp = await self._request(ref.registry, "GET", path, headers=headers, scope=f"repository:{ref.repository}:pull")
        if resp.status_code == 404:
            raise ProviderError(f"OCI manifest not found: {ref.display_registry}/{ref.repository}:{reference}")
        resp.raise_for_status()
        data = resp.content
        digest = resp.headers.get("Docker-Content-Digest") or f"sha256:{sha256_bytes(data)}"
        media_type = resp.headers.get("Content-Type", "").split(";", 1)[0] or "application/vnd.oci.image.manifest.v1+json"
        return data, media_type, digest

    async def _get_blob(self, ref: OCIReference, digest: str, max_bytes: int) -> bytes:
        path = f"/v2/{ref.repository}/blobs/{quote(digest, safe=':')}"
        resp = await self._request(ref.registry, "GET", path, scope=f"repository:{ref.repository}:pull")
        resp.raise_for_status()
        if int(resp.headers.get("Content-Length") or 0) > max_bytes:
            raise ProviderError(f"OCI blob {digest} exceeds maximum size")
        data = resp.content
        if len(data) > max_bytes:
            raise ProviderError(f"OCI blob {digest} exceeds maximum size")
        algo, expected = digest.split(":", 1)
        if algo != "sha256" or sha256_bytes(data) != expected:
            raise ProviderError(f"OCI blob digest mismatch for {digest}")
        return data

    def _select_manifest(self, index: dict[str, Any], platform: str) -> dict[str, Any]:
        os_name, _, arch = platform.partition("/")
        manifests = index.get("manifests") or []
        for item in manifests:
            plat = item.get("platform") or {}
            if plat.get("os") == os_name and plat.get("architecture") == arch:
                return item
        if manifests:
            return manifests[0]
        raise ProviderError("OCI image index has no manifests")

    async def _request(
        self,
        registry: str,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        scope: str | None = None,
    ) -> httpx.Response:
        scheme = "http" if self.allow_http else "https"
        url = f"{scheme}://{registry}{path}"
        async with httpx.AsyncClient(timeout=self.timeout_seconds, follow_redirects=True) as client:
            resp = await client.request(method, url, headers=headers or {}, auth=self._basic_auth())
            if resp.status_code != 401:
                return resp
            challenge = resp.headers.get("WWW-Authenticate", "")
            token = await self._bearer_token(client, challenge, scope)
            if not token:
                return resp
            h = dict(headers or {})
            h["Authorization"] = f"Bearer {token}"
            return await client.request(method, url, headers=h)

    def _basic_auth(self) -> tuple[str, str] | None:
        if self.username and self.password:
            return self.username, self.password
        return None

    async def _bearer_token(self, client: httpx.AsyncClient, challenge: str, fallback_scope: str | None) -> str | None:
        if not challenge.lower().startswith("bearer "):
            return None
        params: dict[str, str] = {}
        for match in re.finditer(r'(\w+)="([^"]*)"', challenge):
            params[match.group(1)] = match.group(2)
        realm = params.get("realm")
        if not realm:
            return None
        query: dict[str, str] = {}
        if params.get("service"):
            query["service"] = params["service"]
        if params.get("scope") or fallback_scope:
            query["scope"] = params.get("scope") or fallback_scope or ""
        url = realm + ("&" if "?" in realm else "?") + urlencode(query)
        resp = await client.get(url, auth=self._basic_auth())
        resp.raise_for_status()
        data = resp.json()
        return data.get("token") or data.get("access_token")
