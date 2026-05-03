from __future__ import annotations

import html
import json
import shutil
from pathlib import Path
from urllib.parse import quote

from .models import ResolvedArtifact
from .utils import normalize_project_name, safe_join, storage_key


class MirrorStore:
    def __init__(self, root: Path, quarantine_root: Path):
        self.root = root
        self.quarantine_root = quarantine_root
        self.root.mkdir(parents=True, exist_ok=True)
        self.quarantine_root.mkdir(parents=True, exist_ok=True)

    def quarantine_path(self, project: str, version: str, filename: str) -> Path:
        project_norm = normalize_project_name(project)
        return safe_join(self.quarantine_root, "pypi", project_norm, version, filename)

    def quarantine_path_for_resolved(self, resolved: ResolvedArtifact) -> Path:
        coordinate = resolved.coordinate
        return safe_join(
            self.quarantine_root,
            coordinate.ecosystem.value,
            storage_key(coordinate.name or coordinate.project or "unnamed"),
            storage_key(str(coordinate.version or "unversioned")),
            resolved.filename,
        )

    def mirror_path(self, project: str, version: str, digest: str, filename: str) -> Path:
        project_norm = normalize_project_name(project)
        return safe_join(self.root, "pypi", project_norm, version, digest, filename)

    def promote(self, source: Path, project: str, version: str, digest: str, filename: str) -> Path:
        destination = self.mirror_path(project, version, digest, filename)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            shutil.copy2(source, destination)
        return destination

    def promote_universal(self, source: Path, digest: str, filename: str) -> Path:
        destination = safe_join(self.root, "files", digest, filename)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.resolve() != destination.resolve() and not destination.exists():
            shutil.copy2(source, destination)
        return destination

    def file_by_digest(self, digest: str, filename: str) -> Path | None:
        direct = safe_join(self.root, "files", digest, filename)
        if direct.is_file():
            return direct
        for candidate in self.root.glob(f"pypi/*/*/{digest}/{filename}"):
            if candidate.is_file():
                return candidate
        return None

    def simple_index_html(self, project: str, rows: list[dict]) -> str:
        project_escaped = html.escape(project)
        links = []
        for row in rows:
            filename = row["filename"]
            digest = row["digest"]
            href = f"/files/{quote(digest)}/{quote(filename)}#sha256={quote(digest)}"
            links.append(f'<a href="{href}">{html.escape(filename)}</a><br/>')
        body = "\n".join(links) if links else ""
        return f"<!doctype html><html><head><title>Links for {project_escaped}</title></head><body><h1>Links for {project_escaped}</h1>{body}</body></html>"

    def npm_packument(self, name: str, rows: list[dict], *, base_url: str = "") -> dict:
        versions: dict[str, dict] = {}
        latest: str | None = None
        for row in rows:
            version = row.get("version") or "0.0.0"
            digest = row["digest"]
            filename = row["filename"]
            resolved = json.loads(row.get("resolved_json") or "{}")
            metadata = resolved.get("metadata") or {}
            versions[version] = {
                "name": name,
                "version": version,
                "license": metadata.get("license"),
                "dist": {
                    "tarball": f"{base_url}/files/{quote(digest)}/{quote(filename)}",
                    "shasum": (resolved.get("expected_digests") or {}).get("sha1"),
                    "integrity": resolved.get("integrity"),
                },
                "palsy": {"digest": digest, "permit_required": True},
            }
            latest = version
        return {
            "name": name,
            "dist-tags": {"latest": latest} if latest else {},
            "versions": versions,
        }
