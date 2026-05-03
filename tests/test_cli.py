from __future__ import annotations

import argparse
import json

import palsy.__main__ as cli


class _FakeResponse:
    def __init__(self, body: dict):
        self._body = json.dumps(body).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return self._body


def test_admit_lockfile_command_returns_zero_for_allow(monkeypatch, tmp_path, capsys):
    lockfile = tmp_path / "requirements.txt"
    lockfile.write_text("idna==3.10\n", encoding="utf-8")

    def fake_urlopen(request, timeout):
        assert timeout == 300
        payload = json.loads(request.data)
        assert payload["lockfile_name"] == "requirements.txt"
        return _FakeResponse(_admission_response("allow", permit_id="permit-1"))

    monkeypatch.setattr(cli.urllib.request, "urlopen", fake_urlopen)

    code = cli.admit_lockfile_command(_args(lockfile))

    assert code == 0
    assert "build permit: permit-1" in capsys.readouterr().out


def test_admit_lockfile_command_returns_one_for_denied_graph(monkeypatch, tmp_path, capsys):
    lockfile = tmp_path / "requirements.txt"
    lockfile.write_text("packaging==24.2\n", encoding="utf-8")

    def fake_urlopen(request, timeout):
        return _FakeResponse(_admission_response("deny"))

    monkeypatch.setattr(cli.urllib.request, "urlopen", fake_urlopen)

    code = cli.admit_lockfile_command(_args(lockfile))

    assert code == 1
    assert "decision: deny" in capsys.readouterr().out


def _args(lockfile):
    return argparse.Namespace(
        lockfile=lockfile,
        project="demo",
        environment="ci",
        url="http://127.0.0.1:8080",
        token="dev-token",
        sandbox=False,
        force_rescan=False,
        timeout=300,
        json_output=False,
    )


def _admission_response(decision: str, permit_id: str | None = None) -> dict:
    return {
        "project": "demo",
        "environment": "ci",
        "lockfile_name": "requirements.txt",
        "lockfile_digest": "a" * 64,
        "dependency_count": 1,
        "decision": decision,
        "reasons": ["1 dependency artefact passed policy"]
        if decision == "allow"
        else ["1 dependency artefact denied"],
        "policy_name": "test",
        "policy_hash": "b" * 64,
        "items": [
            {
                "coordinate": {
                    "ecosystem": "pypi",
                    "project": "idna",
                    "name": "idna",
                    "version": "3.10",
                },
                "decision": decision,
                "reasons": ["all configured checks passed"],
            }
        ],
        "permit": {"id": permit_id} if permit_id else None,
    }
