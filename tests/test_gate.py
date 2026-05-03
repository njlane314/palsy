from __future__ import annotations

import argparse
from datetime import timedelta

from palsy import gate
from palsy.models import BuildPermit, BuildPermitSubject, Decision, Environment
from palsy.permits import PermitSigner
from palsy.utils import sha256_bytes, utcnow


def test_init_command_writes_policy_and_github_workflow(tmp_path, capsys):
    code = gate.init_command(
        argparse.Namespace(
            directory=tmp_path,
            force=False,
            github_actions=True,
            gitlab_ci=False,
        )
    )

    assert code == 0
    assert (tmp_path / ".palsy" / "policy.yaml").is_file()
    assert (tmp_path / ".palsy" / ".gitignore").is_file()
    assert (tmp_path / ".github" / "workflows" / "palsy.yml").is_file()
    output = capsys.readouterr().out
    assert "Palsy Gate initialised" in output
    assert "palsy gate --mode observe" in output


def test_verify_permit_command_accepts_valid_build_permit(tmp_path, capsys):
    lockfile = tmp_path / "requirements.txt"
    lockfile.write_text("idna==3.10\n", encoding="utf-8")

    signer = PermitSigner(tmp_path / "key.pem")
    permit = signer.sign_build_permit(
        BuildPermit(
            subject=BuildPermitSubject(
                project="demo",
                lockfile_name="requirements.txt",
                lockfile_digest=sha256_bytes(lockfile.read_bytes()),
                dependency_count=1,
                artifact_digests=["a" * 64],
            ),
            decision=Decision.allow,
            environment=Environment.ci,
            policy_name="test",
            policy_hash="b" * 64,
            expires_at=utcnow() + timedelta(days=1),
            reasons=["1 dependency artefact passed policy"],
        )
    )
    permit_path = tmp_path / "permit.json"
    permit_path.write_text(permit.model_dump_json(), encoding="utf-8")

    code = gate.verify_permit_command(
        argparse.Namespace(
            permit=permit_path,
            lockfile=lockfile,
            project="demo",
            environment="ci",
        )
    )

    assert code == 0
    assert "Build permit verified" in capsys.readouterr().out


def test_verify_permit_command_rejects_tampered_build_permit(tmp_path, capsys):
    lockfile = tmp_path / "requirements.txt"
    lockfile.write_text("idna==3.10\n", encoding="utf-8")

    signer = PermitSigner(tmp_path / "key.pem")
    permit = signer.sign_build_permit(
        BuildPermit(
            subject=BuildPermitSubject(
                project="demo",
                lockfile_name="requirements.txt",
                lockfile_digest=sha256_bytes(lockfile.read_bytes()),
                dependency_count=1,
                artifact_digests=["a" * 64],
            ),
            decision=Decision.allow,
            environment=Environment.ci,
            policy_name="test",
            policy_hash="b" * 64,
            expires_at=utcnow() + timedelta(days=1),
            reasons=["1 dependency artefact passed policy"],
        )
    )
    tampered = permit.model_copy(update={"policy_name": "tampered"})
    permit_path = tmp_path / "permit.json"
    permit_path.write_text(tampered.model_dump_json(), encoding="utf-8")

    code = gate.verify_permit_command(
        argparse.Namespace(
            permit=permit_path,
            lockfile=lockfile,
            project="demo",
            environment="ci",
        )
    )

    assert code == 1
    assert "signature is invalid" in capsys.readouterr().err
