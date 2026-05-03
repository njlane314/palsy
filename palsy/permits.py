from __future__ import annotations

import base64
import binascii
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel

from .models import BuildPermit, Permit
from .utils import canonical_json


def verify_signed_model(model: BaseModel) -> bool:
    try:
        public_key = getattr(model, "public_key")
        encoded_signature = getattr(model, "signature")
        if not public_key or not encoded_signature:
            return False
        public = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key))
        signature = base64.b64decode(encoded_signature)
        unsigned = model.model_copy(update={"signature": None})
        public.verify(signature, _payload(unsigned))
        return True
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return False


def verify_build_permit_document(permit: BuildPermit) -> bool:
    return verify_signed_model(permit)


class PermitSigner:
    def __init__(self, key_path: Path):
        self.key_path = key_path
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        self._private_key = self._load_or_create()
        self._public_key = self._private_key.public_key()

    def _load_or_create(self) -> Ed25519PrivateKey:
        if self.key_path.exists():
            data = self.key_path.read_bytes()
            key = serialization.load_pem_private_key(data, password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise TypeError("configured signing key is not Ed25519")
            return key
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.key_path.write_bytes(pem)
        self.key_path.chmod(0o600)
        return key

    @property
    def public_key_b64(self) -> str:
        raw = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(raw).decode("ascii")

    def sign(self, permit: Permit) -> Permit:
        return self._sign_model(permit)

    def verify(self, permit: Permit) -> bool:
        return self._verify_model(permit)

    def sign_build_permit(self, permit: BuildPermit) -> BuildPermit:
        return self._sign_model(permit)

    def verify_build_permit(self, permit: BuildPermit) -> bool:
        return self._verify_model(permit)

    def _sign_model(self, model: BaseModel):
        signed = model.model_copy(update={"public_key": self.public_key_b64, "signature": None})
        signature = self._private_key.sign(self._payload(signed))
        return signed.model_copy(update={"signature": base64.b64encode(signature).decode("ascii")})

    def _verify_model(self, model: BaseModel) -> bool:
        return verify_signed_model(model)

    def _payload(self, model: BaseModel) -> bytes:
        return _payload(model)


def _payload(model: BaseModel) -> bytes:
    data = model.model_dump(mode="json", exclude={"signature"})
    return canonical_json(data)
