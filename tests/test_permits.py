from __future__ import annotations

from datetime import timedelta

from palsy.models import Decision, Environment, Permit, PermitSubject, ScanCapabilities
from palsy.permits import PermitSigner
from palsy.utils import utcnow


def test_permit_sign_and_verify(tmp_path):
    signer = PermitSigner(tmp_path / "ed25519.pem")
    permit = Permit(
        subject=PermitSubject(project="demo", version="1.0.0", filename="demo.whl", digest="a" * 64),
        decision=Decision.allow,
        environment=Environment.ci,
        policy_name="test",
        policy_hash="b" * 64,
        expires_at=utcnow() + timedelta(days=1),
        capabilities=ScanCapabilities(),
    )
    signed = signer.sign(permit)
    assert signed.signature
    assert signer.verify(signed)
    tampered = signed.model_copy(deep=True)
    tampered.subject.version = "9.9.9"
    assert not signer.verify(tampered)
