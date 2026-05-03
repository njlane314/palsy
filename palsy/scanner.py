from __future__ import annotations

import ast
import base64
import csv
import hashlib
import io
import math
import re
import tarfile
import zipfile
from pathlib import PurePosixPath, Path
from typing import Iterable

from .models import Finding, ScanCapabilities, ScanReport, Severity
from .utils import b64url_decode_nopad, sha256_file

NATIVE_EXTENSIONS = {
    ".so",
    ".pyd",
    ".dll",
    ".dylib",
    ".exe",
    ".bin",
    ".a",
    ".o",
    ".wasm",
}
ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar"}
TEXT_EXTENSIONS = {
    ".py",
    ".pth",
    ".txt",
    ".js",
    ".json",
    ".toml",
    ".cfg",
    ".ini",
    ".yaml",
    ".yml",
    ".sh",
    ".ps1",
    ".bat",
    ".cmd",
    ".pyi",
}
CREDENTIAL_RE = re.compile(
    r"(AWS_|AZURE_|GCP_|GOOGLE_|SECRET|TOKEN|PRIVATE_KEY|id_rsa|\.ssh|\.npmrc|pypirc|"
    r"kubeconfig|service_account|credentials|password|api[_-]?key)",
    re.IGNORECASE,
)
NETWORK_RE = re.compile(
    r"(https?://|socket\.|requests\.|urllib\.|httpx\.|aiohttp\.|ftplib\.|paramiko\.|"
    r"169\.254\.169\.254|metadata\.google\.internal)",
    re.IGNORECASE,
)
SUBPROCESS_RE = re.compile(r"(subprocess\.|os\.system\(|os\.popen\(|pty\.spawn\(|exec\(|eval\()")
PTH_EXEC_RE = re.compile(r"^\s*import[ \t]", re.MULTILINE)
BASE64ISH_RE = re.compile(r"[A-Za-z0-9+/=_-]{512,}")
URL_RE = re.compile(r"https?://[^\s'\"<>]+")


class StaticArtifactScanner:
    """Static scanner for PyPI wheels and source distributions.

    It intentionally does not extract archives to disk. Archive traversal and zip-slip
    properties are evaluated from member metadata only.
    """

    def scan(self, path: Path, digest: str | None = None) -> ScanReport:
        digest = digest or sha256_file(path)
        report = ScanReport(artifact_digest=digest, artifact_filename=path.name)
        if path.name.endswith(".whl"):
            report.capabilities.contains_wheel = True
            self._scan_wheel(path, report)
        elif path.name.endswith((".tar.gz", ".tgz", ".tar", ".zip")):
            report.capabilities.contains_sdist = True
            self._scan_sdist(path, report)
        else:
            self._add(
                report,
                "artifact.unsupported_format",
                Severity.medium,
                "Unsupported artefact format",
                f"The artefact {path.name!r} is not a wheel or recognised sdist archive.",
                location=path.name,
            )
        return report

    def _add(
        self,
        report: ScanReport,
        rule_id: str,
        severity: Severity,
        title: str,
        description: str,
        location: str | None = None,
        **evidence: object,
    ) -> None:
        report.findings.append(
            Finding(
                rule_id=rule_id,
                severity=severity,
                title=title,
                description=description,
                location=location,
                evidence={k: v for k, v in evidence.items() if v is not None},
            )
        )

    def _scan_wheel(self, path: Path, report: ScanReport) -> None:
        try:
            with zipfile.ZipFile(path) as zf:
                infos = zf.infolist()
                report.file_count = len(infos)
                report.total_uncompressed_size = sum(info.file_size for info in infos)
                names = [info.filename for info in infos]
                self._scan_member_names(names, report)
                self._parse_wheel_metadata(zf, names, report)
                self._validate_record(zf, names, report)
                for info in infos:
                    self._scan_archive_member(info.filename, info.file_size, lambda n=info.filename: zf.read(n), report)
                report.top_level_modules = sorted(self._infer_top_level_modules(names, report))
        except zipfile.BadZipFile:
            self._add(
                report,
                "artifact.bad_zip",
                Severity.critical,
                "Invalid wheel ZIP file",
                "The wheel could not be parsed as a ZIP archive.",
                location=path.name,
            )

    def _scan_sdist(self, path: Path, report: ScanReport) -> None:
        if path.name.endswith(".zip"):
            try:
                with zipfile.ZipFile(path) as zf:
                    infos = zf.infolist()
                    report.file_count = len(infos)
                    report.total_uncompressed_size = sum(info.file_size for info in infos)
                    names = [info.filename for info in infos]
                    self._scan_member_names(names, report)
                    for info in infos:
                        self._scan_archive_member(info.filename, info.file_size, lambda n=info.filename: zf.read(n), report)
            except zipfile.BadZipFile:
                self._add(report, "artifact.bad_zip", Severity.critical, "Invalid sdist ZIP", "Could not parse sdist ZIP.", path.name)
            return

        try:
            mode = "r:gz" if path.name.endswith((".tar.gz", ".tgz")) else "r:*"
            with tarfile.open(path, mode) as tf:
                members = [m for m in tf.getmembers() if m.isfile()]
                report.file_count = len(members)
                report.total_uncompressed_size = sum(m.size for m in members)
                names = [m.name for m in members]
                self._scan_member_names(names, report)
                for member in members:
                    def read_member(m=member) -> bytes:
                        f = tf.extractfile(m)
                        return f.read() if f else b""

                    self._scan_archive_member(member.name, member.size, read_member, report)
        except tarfile.TarError:
            self._add(report, "artifact.bad_tar", Severity.critical, "Invalid sdist tar archive", "Could not parse sdist tar archive.", path.name)

    def _scan_member_names(self, names: list[str], report: ScanReport) -> None:
        for name in names:
            pure = PurePosixPath(name)
            if name.startswith("/") or ".." in pure.parts:
                report.capabilities.path_traversal = True
                self._add(
                    report,
                    "archive.path_traversal",
                    Severity.critical,
                    "Archive path traversal entry",
                    "The artefact contains an archive member that could escape the target directory if extracted unsafely.",
                    location=name,
                )
            parts_lower = [p.lower() for p in pure.parts]
            suffix = pure.suffix.lower()
            if suffix in NATIVE_EXTENSIONS:
                report.capabilities.has_native_code = True
                self._add(
                    report,
                    "artifact.native_code",
                    Severity.medium,
                    "Native or executable file present",
                    "The artefact contains a native binary or executable payload.",
                    location=name,
                    suffix=suffix,
                )
            if any(p.startswith(".") for p in parts_lower) or any(p in {"_runtime", "runtime", "runtimes"} for p in parts_lower):
                report.capabilities.has_hidden_runtime = True
                self._add(
                    report,
                    "artifact.hidden_runtime_dir",
                    Severity.high,
                    "Hidden or runtime directory present",
                    "The artefact contains hidden/runtime-like directories often used to stage secondary payloads.",
                    location=name,
                )
            if any(p in {"bun", "node", "nodejs", "deno"} for p in parts_lower) or any(
                p.startswith(("bun-", "node-", "deno-")) for p in parts_lower
            ):
                report.capabilities.has_embedded_interpreter = True
                self._add(
                    report,
                    "artifact.embedded_interpreter",
                    Severity.high,
                    "Embedded non-Python runtime present",
                    "The artefact appears to include or stage another interpreter/runtime.",
                    location=name,
                )
            if pure.name in {"sitecustomize.py", "usercustomize.py"}:
                report.capabilities.has_startup_hook = True
                self._add(
                    report,
                    "python.startup_customize",
                    Severity.high,
                    "Python startup customisation file",
                    "sitecustomize.py or usercustomize.py executes at interpreter startup when importable.",
                    location=name,
                )
            if pure.name in {"setup.py", "pyproject.toml"}:
                report.capabilities.has_install_hook = True

    def _scan_archive_member(self, name: str, size: int, read_bytes, report: ScanReport) -> None:
        pure = PurePosixPath(name)
        suffix = pure.suffix.lower()
        if size > 5 * 1024 * 1024 and suffix in {".js", ".py", ".txt", ".json"}:
            report.capabilities.has_large_obfuscated_blob = True
            self._add(
                report,
                "artifact.large_text_blob",
                Severity.high,
                "Large text payload",
                "The artefact contains a large source/text blob, commonly seen in packed or obfuscated payloads.",
                location=name,
                size=size,
            )
        if suffix not in TEXT_EXTENSIONS:
            return
        if size > 2 * 1024 * 1024:
            # Avoid spending excessive CPU on giant files; large text files are already reported.
            return
        try:
            data = read_bytes()
        except Exception as exc:  # pragma: no cover - defensive
            self._add(report, "artifact.member_read_error", Severity.medium, "Could not read member", str(exc), name)
            return
        text = data.decode("utf-8", errors="ignore")
        if suffix == ".pth":
            self._scan_pth(name, text, report)
        if suffix == ".py":
            self._scan_python(name, text, report)
        else:
            self._scan_text(name, text, report)

    def _scan_pth(self, name: str, text: str, report: ScanReport) -> None:
        executable_lines = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if re.match(r"^\s*import[ \t]", line):
                executable_lines.append({"line": lineno, "text": line[:300]})
        if executable_lines:
            report.capabilities.has_pth_exec = True
            report.capabilities.has_startup_hook = True
            self._add(
                report,
                "python.pth_exec",
                Severity.critical,
                "Executable .pth startup hook",
                "The .pth file contains import lines that execute during Python site initialisation.",
                location=name,
                executable_lines=executable_lines,
            )
        self._scan_text(name, text, report)

    def _scan_python(self, name: str, text: str, report: ScanReport) -> None:
        self._scan_text(name, text, report)
        if PurePosixPath(name).name == "__init__.py" and any(
            pattern.search(text) for pattern in [NETWORK_RE, SUBPROCESS_RE, CREDENTIAL_RE]
        ):
            report.capabilities.import_time_sensitive = True
            self._add(
                report,
                "python.init_sensitive_behaviour",
                Severity.high,
                "Sensitive behaviour in package __init__.py",
                "Top-level package initialisation references networking, subprocess execution, or credentials.",
                location=name,
            )
        try:
            tree = ast.parse(text, filename=name)
        except SyntaxError:
            return
        imports = self._top_level_imports(tree)
        if "subprocess" in imports:
            report.capabilities.imports_subprocess = True
        if "socket" in imports:
            report.capabilities.imports_socket = True
        sensitive_calls = self._top_level_sensitive_calls(tree)
        if sensitive_calls:
            report.capabilities.import_time_sensitive = True
            self._add(
                report,
                "python.top_level_sensitive_call",
                Severity.high,
                "Sensitive top-level Python call",
                "The module performs sensitive work at import time rather than inside a function.",
                location=name,
                calls=sensitive_calls[:20],
            )

    def _scan_text(self, name: str, text: str, report: ScanReport) -> None:
        if CREDENTIAL_RE.search(text):
            report.capabilities.references_credentials = True
            self._add(
                report,
                "artifact.credential_reference",
                Severity.medium,
                "Credential-related strings present",
                "The artefact references credentials, tokens, keys, cloud metadata, or secret file names.",
                location=name,
            )
        urls = sorted(set(URL_RE.findall(text)))[:20]
        if NETWORK_RE.search(text) or urls:
            report.capabilities.references_network = True
            self._add(
                report,
                "artifact.network_reference",
                Severity.low,
                "Network-related strings present",
                "The artefact references URLs, sockets, HTTP clients, or cloud metadata endpoints.",
                location=name,
                urls=urls,
            )
        long_lines = [len(line) for line in text.splitlines() if len(line) > 4000]
        b64_hits = BASE64ISH_RE.findall(text)
        if long_lines or len(b64_hits) >= 3 or self._entropy(text[:100000]) > 5.2:
            report.capabilities.has_large_obfuscated_blob = True
            self._add(
                report,
                "artifact.obfuscation_signal",
                Severity.high,
                "Obfuscation or packed-code signal",
                "The artefact contains unusually long lines, base64-like blobs, or high-entropy text.",
                location=name,
                long_line_count=len(long_lines),
                base64ish_count=len(b64_hits),
            )

    def _parse_wheel_metadata(self, zf: zipfile.ZipFile, names: list[str], report: ScanReport) -> None:
        metadata_name = next((n for n in names if n.endswith(".dist-info/METADATA")), None)
        wheel_name = next((n for n in names if n.endswith(".dist-info/WHEEL")), None)
        top_level_name = next((n for n in names if n.endswith(".dist-info/top_level.txt")), None)
        if metadata_name:
            text = zf.read(metadata_name).decode("utf-8", errors="ignore")
            report.metadata["metadata_name"] = metadata_name
            report.metadata["requires_dist"] = [
                line.split(":", 1)[1].strip()
                for line in text.splitlines()
                if line.startswith("Requires-Dist:")
            ]
            for field in ["Name", "Version", "Summary", "Author", "Maintainer"]:
                prefix = f"{field}:"
                for line in text.splitlines():
                    if line.startswith(prefix):
                        report.metadata[field.lower()] = line.split(":", 1)[1].strip()
                        break
        if wheel_name:
            text = zf.read(wheel_name).decode("utf-8", errors="ignore")
            report.metadata["wheel_name"] = wheel_name
            report.metadata["wheel"] = {
                line.split(":", 1)[0].strip(): line.split(":", 1)[1].strip()
                for line in text.splitlines()
                if ":" in line
            }
        if top_level_name:
            text = zf.read(top_level_name).decode("utf-8", errors="ignore")
            report.metadata["declared_top_level"] = [
                line.strip() for line in text.splitlines() if line.strip()
            ]

    def _validate_record(self, zf: zipfile.ZipFile, names: list[str], report: ScanReport) -> None:
        record_name = next((n for n in names if n.endswith(".dist-info/RECORD")), None)
        if not record_name:
            report.capabilities.record_missing = True
            self._add(
                report,
                "wheel.record_missing",
                Severity.high,
                "Wheel RECORD file missing",
                "The wheel lacks the RECORD file needed to verify file hashes inside the archive.",
            )
            return
        data = zf.read(record_name).decode("utf-8", errors="replace")
        reader = csv.reader(io.StringIO(data))
        checked = 0
        failures = []
        zip_names = set(names)
        for row in reader:
            if len(row) < 3:
                continue
            member, hash_spec, _size = row[:3]
            if member == record_name or not hash_spec:
                continue
            if member not in zip_names:
                failures.append({"member": member, "reason": "missing from archive"})
                continue
            try:
                algo, expected_b64 = hash_spec.split("=", 1)
            except ValueError:
                failures.append({"member": member, "reason": "malformed hash spec"})
                continue
            if algo.lower() != "sha256":
                continue
            actual = hashlib.sha256(zf.read(member)).digest()
            expected = b64url_decode_nopad(expected_b64)
            checked += 1
            if actual != expected:
                failures.append({"member": member, "reason": "sha256 mismatch"})
        if failures:
            self._add(
                report,
                "wheel.record_hash_mismatch",
                Severity.critical,
                "Wheel RECORD hash mismatch",
                "One or more files do not match hashes listed in RECORD.",
                location=record_name,
                failures=failures[:50],
            )
        elif checked > 0:
            report.capabilities.record_validated = True

    def _infer_top_level_modules(self, names: Iterable[str], report: ScanReport) -> set[str]:
        declared = report.metadata.get("declared_top_level")
        if declared:
            return {str(item) for item in declared}
        top: set[str] = set()
        for name in names:
            pure = PurePosixPath(name)
            parts = pure.parts
            if not parts:
                continue
            if ".dist-info" in parts[0] or ".data" in parts[0]:
                continue
            first = parts[0]
            if first.endswith(".py") and first != "setup.py":
                top.add(first[:-3])
            elif len(parts) > 1 and not first.startswith(".") and first not in {"bin", "scripts"}:
                top.add(first)
        return {item for item in top if item and item.isidentifier()}

    def _top_level_imports(self, tree: ast.Module) -> set[str]:
        imports: set[str] = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
        return imports

    def _top_level_sensitive_calls(self, tree: ast.Module) -> list[str]:
        sensitive = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            for call in [n for n in ast.walk(node) if isinstance(n, ast.Call)]:
                name = self._call_name(call.func)
                if name and (
                    name.startswith("subprocess.")
                    or name in {"os.system", "os.popen", "eval", "exec", "compile", "open"}
                    or name.startswith("requests.")
                    or name.startswith("httpx.")
                    or name.startswith("urllib.")
                    or name.startswith("socket.")
                ):
                    sensitive.append(name)
        return sensitive

    def _call_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = self._call_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return None

    def _entropy(self, text: str) -> float:
        if not text:
            return 0.0
        counts: dict[str, int] = {}
        for ch in text:
            counts[ch] = counts.get(ch, 0) + 1
        n = len(text)
        return -sum((count / n) * math.log2(count / n) for count in counts.values())
