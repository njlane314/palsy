from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import zipfile
from pathlib import Path

from palsy.scanner import StaticArtifactScanner


EXAMPLE_DIR = Path(__file__).resolve().parent
ARTEFACT_DIR = EXAMPLE_DIR / "artefacts"
WHEEL_PATH = ARTEFACT_DIR / "palsy_demo-1.0.0-py3-none-any.whl"
REPORT_PATH = ARTEFACT_DIR / "palsy_demo_scan_report.json"


def record_hash(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"sha256={encoded}"


def write_demo_wheel(path: Path) -> Path:
    dist_info = "palsy_demo-1.0.0.dist-info"
    files = {
        "palsy_demo/__init__.py": (
            b"import subprocess\n"
            b"subprocess.Popen(['echo', 'demo import-time side effect'])\n"
            b"__version__ = '1.0.0'\n"
        ),
        "palsy_demo_startup.pth": b"import os; os.system('echo demo startup hook')\n",
        f"{dist_info}/METADATA": (
            b"Metadata-Version: 2.1\n"
            b"Name: palsy-demo\n"
            b"Version: 1.0.0\n"
            b"Summary: Demo package with suspicious startup behaviour\n"
        ),
        f"{dist_info}/WHEEL": (
            b"Wheel-Version: 1.0\n"
            b"Generator: palsy example\n"
            b"Root-Is-Purelib: true\n"
            b"Tag: py3-none-any\n"
        ),
        f"{dist_info}/top_level.txt": b"palsy_demo\n",
    }

    record_name = f"{dist_info}/RECORD"
    record_rows = io.StringIO()
    writer = csv.writer(record_rows, lineterminator="\n")
    for filename, data in sorted(files.items()):
        writer.writerow([filename, record_hash(data), str(len(data))])
    writer.writerow([record_name, "", ""])
    files[record_name] = record_rows.getvalue().encode("utf-8")

    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as wheel:
        for filename, data in files.items():
            wheel.writestr(filename, data)
    return path


def main() -> None:
    wheel_path = write_demo_wheel(WHEEL_PATH)
    report = StaticArtifactScanner().scan(wheel_path)
    REPORT_PATH.write_text(
        json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    enabled_capabilities = {
        name: value for name, value in report.capabilities.model_dump().items() if value
    }

    print(f"created: {wheel_path}")
    print(f"report: {REPORT_PATH}")
    print(f"digest: {report.artifact_digest}")
    print(f"max severity: {report.max_severity.value}")
    print(f"files scanned: {report.file_count}")
    print("capabilities:")
    for name in sorted(enabled_capabilities):
        print(f"  - {name}")
    print("findings:")
    for finding in report.findings:
        location = finding.location or report.artifact_filename
        print(f"  - [{finding.severity.value}] {finding.rule_id}: {finding.title} ({location})")


if __name__ == "__main__":
    main()
