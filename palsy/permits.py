from __future__ import annotations

import base64
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .models import Permit
from .utils import canonical_json


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
        permit.public_key = self.public_key_b64
        permit.signature = None
        signature = self._private_key.sign(self._payload(permit))
        permit.signature = base64.b64encode(signature).decode("ascii")
        return permit

    def verify(self, permit: Permit) -> bool:
        if not permit.signature or not permit.public_key:
            return False
        try:
            public = Ed25519PublicKey.from_public_bytes(base64.b64decode(permit.public_key))
            signature = base64.b64decode(permit.signature)
            unsigned = permit.model_copy(update={"signature": None})
            public.verify(signature, self._payload(unsigned))
            return True
        except (InvalidSignature, ValueError):
            return False

    def _payload(self, permit: Permit) -> bytes:
        data = permit.model_dump(mode="json", exclude={"signature"})
        return canonical_json(data)
