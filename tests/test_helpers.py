from __future__ import annotations

import base64
import csv
import hashlib
import io
import zipfile
from pathlib import Path


def _record_hash(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def write_wheel(path: Path, name: str = "demo", version: str = "1.0.0", files: dict[str, bytes] | None = None) -> Path:
    files = dict(files or {})
    dist = f"{name}-{version}.dist-info"
    metadata_name = f"{dist}/METADATA"
    wheel_name = f"{dist}/WHEEL"
    top_name = f"{dist}/top_level.txt"
    files.setdefault(f"{name}/__init__.py", b"__version__='1.0.0'\n")
    files.setdefault(metadata_name, f"Name: {name}\nVersion: {version}\n".encode())
    files.setdefault(wheel_name, b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
    files.setdefault(top_name, f"{name}\n".encode())
    record_name = f"{dist}/RECORD"
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    for fname, data in sorted(files.items()):
        writer.writerow([fname, _record_hash(data), str(len(data))])
    writer.writerow([record_name, "", ""])
    files[record_name] = out.getvalue().encode()
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname, data in files.items():
            zf.writestr(fname, data)
    return path
