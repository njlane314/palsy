from __future__ import annotations

import html
import shutil
from pathlib import Path
from urllib.parse import quote

from .utils import normalize_project_name, safe_join


class MirrorStore:
    def __init__(self, root: Path, quarantine_root: Path):
        self.root = root
        self.quarantine_root = quarantine_root
        self.root.mkdir(parents=True, exist_ok=True)
        self.quarantine_root.mkdir(parents=True, exist_ok=True)

    def quarantine_path(self, project: str, version: str, filename: str) -> Path:
        project_norm = normalize_project_name(project)
        return safe_join(self.quarantine_root, "pypi", project_norm, version, filename)

    def mirror_path(self, project: str, version: str, digest: str, filename: str) -> Path:
        project_norm = normalize_project_name(project)
        return safe_join(self.root, "pypi", project_norm, version, digest, filename)

    def promote(self, source: Path, project: str, version: str, digest: str, filename: str) -> Path:
        destination = self.mirror_path(project, version, digest, filename)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            shutil.copy2(source, destination)
        return destination

    def file_by_digest(self, digest: str, filename: str) -> Path | None:
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
