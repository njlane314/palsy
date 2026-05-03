from __future__ import annotations

import asyncio
import json
import tempfile
import textwrap
import time
from pathlib import Path

from .models import DynamicEvent, SandboxReport, Severity

HARNESS = r'''
import importlib
import json
import os
import pathlib
import socket
import subprocess
import sys
import traceback

PREFIX = "PALSY_EVENT "
SECRET_HINTS = ("AWS_", "AZURE_", "GCP_", "GOOGLE_", "TOKEN", "SECRET", "PASSWORD", "PRIVATE", "SSH", "KUBE", "CREDENTIAL")
PATH_HINTS = (".ssh", "id_rsa", ".aws", ".config/gcloud", ".kube", ".npmrc", ".pypirc", "credentials")

def emit(kind, detail, severity="info", **evidence):
    print(PREFIX + json.dumps({"kind": kind, "detail": detail, "severity": severity, "evidence": evidence}, sort_keys=True), flush=True)

# Fake secrets. A legitimate import path should not need these.
os.environ.setdefault("AWS_ACCESS_KEY_ID", "AKIA_FAKE_CANARY_DO_NOT_USE")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "PALSY_FAKE_SECRET_CANARY")
os.environ.setdefault("GITHUB_TOKEN", "ghp_fake_canary_token")
os.environ.setdefault("NPM_TOKEN", "npm_fake_canary_token")

home = pathlib.Path.home()
for rel, content in {
    ".ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nPALSY_FAKE_CANARY\n-----END OPENSSH PRIVATE KEY-----\n",
    ".aws/credentials": "[default]\naws_access_key_id=AKIA_FAKE_CANARY\naws_secret_access_key=PALSY_FAKE_SECRET\n",
    ".kube/config": "apiVersion: v1\nclusters: []\n",
    ".pypirc": "[pypi]\nusername=__token__\npassword=pypi-FAKE\n",
}.items():
    p = home / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)

# Audit hooks catch many Python-level operations without executing inside the firewall process.
def audit(event, args):
    try:
        if event in {"open", "os.system", "subprocess.Popen", "socket.connect", "socket.getaddrinfo"}:
            detail = repr(args)[:1000]
            sev = "medium"
            if any(h in detail for h in PATH_HINTS) or "169.254.169.254" in detail or "metadata.google.internal" in detail:
                sev = "high"
            emit("audit." + event, detail, sev)
    except Exception:
        pass

sys.addaudithook(audit)

# Monkeypatch os.getenv to make environment probing explicit. os.environ direct reads may not be caught.
_orig_getenv = os.getenv
def getenv_hook(key, default=None):
    if any(h in str(key).upper() for h in SECRET_HINTS):
        emit("env.read", str(key), "high")
    return _orig_getenv(key, default)
os.getenv = getenv_hook

# Monkeypatch subprocess and socket for clearer signal. Network is disabled by Docker regardless.
_orig_popen = subprocess.Popen
def popen_hook(*a, **kw):
    emit("process.spawn", repr(a)[:1000], "high")
    return _orig_popen(*a, **kw)
subprocess.Popen = popen_hook

_orig_connect = socket.socket.connect
def connect_hook(self, address):
    emit("network.connect", repr(address), "high")
    return _orig_connect(self, address)
socket.socket.connect = connect_hook

wheel = sys.argv[1]
modules = sys.argv[2:]

emit("sandbox.start", "installing wheel with --no-index --no-deps", "info", wheel=wheel)
try:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--no-index", "--no-deps", wheel])
except subprocess.CalledProcessError as exc:
    emit("install.error", f"pip install failed: {exc}", "medium", returncode=exc.returncode)

for mod in modules:
    try:
        emit("import.start", mod, "info")
        importlib.import_module(mod)
        emit("import.ok", mod, "info")
    except Exception as exc:
        emit("import.error", mod, "medium", error=repr(exc), traceback=traceback.format_exc(limit=10))
'''


class DockerSandboxRunner:
    def __init__(self, image: str = "python:3.12-slim", timeout_seconds: int = 20):
        self.image = image
        self.timeout_seconds = timeout_seconds

    async def run(self, artifact_path: Path, top_level_modules: list[str]) -> SandboxReport:
        report = SandboxReport(enabled=True, executed=False)
        modules = [m for m in top_level_modules if m.isidentifier()][:20]
        with tempfile.TemporaryDirectory(prefix="palsy-sandbox-") as tmpdir:
            tmp = Path(tmpdir)
            harness = tmp / "run.py"
            harness.write_text(HARNESS)
            cmd = [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "128",
                "--memory",
                "512m",
                "--cpus",
                "1",
                "-v",
                f"{artifact_path.resolve()}:/input/artifact:ro",
                "-v",
                f"{harness.resolve()}:/harness/run.py:ro",
                self.image,
                "python",
                "/harness/run.py",
                "/input/artifact",
                *modules,
            ]
            start = time.monotonic()
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                report.executed = True
                try:
                    stdout_b, stderr_b = await asyncio.wait_for(
                        proc.communicate(), timeout=self.timeout_seconds
                    )
                except asyncio.TimeoutError:
                    proc.kill()
                    stdout_b, stderr_b = await proc.communicate()
                    report.timeout = True
                    report.events.append(
                        DynamicEvent(
                            kind="sandbox.timeout",
                            detail=f"sandbox exceeded {self.timeout_seconds}s",
                            severity=Severity.high,
                        )
                    )
                report.exit_code = proc.returncode
                report.stdout = stdout_b.decode("utf-8", errors="replace")[-20000:]
                report.stderr = stderr_b.decode("utf-8", errors="replace")[-20000:]
                report.success = proc.returncode == 0 and not report.timeout
                report.duration_ms = int((time.monotonic() - start) * 1000)
                report.events.extend(self._parse_events(report.stdout))
                if proc.returncode not in (0, None):
                    report.events.append(
                        DynamicEvent(
                            kind="sandbox.nonzero_exit",
                            detail=f"container exited with code {proc.returncode}",
                            severity=Severity.medium,
                        )
                    )
            except FileNotFoundError:
                report.events.append(
                    DynamicEvent(
                        kind="sandbox.docker_missing",
                        detail="docker executable is not available on this host",
                        severity=Severity.high,
                    )
                )
            except Exception as exc:  # pragma: no cover - defensive
                report.events.append(
                    DynamicEvent(kind="sandbox.error", detail=repr(exc), severity=Severity.high)
                )
        return report

    def _parse_events(self, stdout: str) -> list[DynamicEvent]:
        events: list[DynamicEvent] = []
        for line in stdout.splitlines():
            if not line.startswith("PALSY_EVENT "):
                continue
            try:
                payload = json.loads(line[len("PALSY_EVENT ") :])
                events.append(DynamicEvent.model_validate(payload))
            except Exception:
                continue
        return events


async def run_sandbox_if_enabled(
    backend: str, artifact_path: Path, top_level_modules: list[str], timeout_seconds: int
) -> SandboxReport | None:
    if backend == "none":
        return SandboxReport(enabled=False, executed=False)
    if backend == "docker":
        return await DockerSandboxRunner(timeout_seconds=timeout_seconds).run(artifact_path, top_level_modules)
    return SandboxReport(enabled=False, executed=False)
