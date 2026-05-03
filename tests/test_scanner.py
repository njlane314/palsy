from __future__ import annotations

from palsy.models import Severity
from palsy.scanner import StaticArtifactScanner

from .test_helpers import write_wheel


def test_scanner_detects_executable_pth(tmp_path):
    wheel = write_wheel(
        tmp_path / "demo-1.0.0-py3-none-any.whl",
        files={"demo_hook.pth": b"import os; os.system('echo bad')\n"},
    )
    report = StaticArtifactScanner().scan(wheel)
    assert report.capabilities.has_pth_exec is True
    assert any(f.rule_id == "python.pth_exec" and f.severity == Severity.critical for f in report.findings)


def test_scanner_detects_sensitive_init(tmp_path):
    wheel = write_wheel(
        tmp_path / "demo-1.0.0-py3-none-any.whl",
        files={"demo/__init__.py": b"import subprocess\nsubprocess.Popen(['echo','x'])\n"},
    )
    report = StaticArtifactScanner().scan(wheel)
    assert report.capabilities.import_time_sensitive is True
    assert any(f.rule_id == "python.top_level_sensitive_call" for f in report.findings)


def test_scanner_validates_record(tmp_path):
    wheel = write_wheel(tmp_path / "demo-1.0.0-py3-none-any.whl")
    report = StaticArtifactScanner().scan(wheel)
    assert report.capabilities.record_validated is True
    assert not any(f.rule_id == "wheel.record_hash_mismatch" for f in report.findings)
