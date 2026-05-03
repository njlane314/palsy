from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

NORMALIZE_RE = re.compile(r"[-_.]+")


def normalize_project_name(name: str) -> str:
    return NORMALIZE_RE.sub("-", name).lower().strip()


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def b64url_decode_nopad(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)


def safe_join(base: Path, *parts: str) -> Path:
    candidate = (base / Path(*parts)).resolve()
    base_resolved = base.resolve()
    if not str(candidate).startswith(str(base_resolved)):
        raise ValueError(f"path escapes base directory: {candidate}")
    return candidate
