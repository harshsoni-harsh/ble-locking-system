import base64
import binascii
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence, Tuple, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)

from .utils import derive_phone_hash, normalize_mac

ROOT_DIR = Path(__file__).resolve().parent.parent
KEYS_DIR = ROOT_DIR / "keys"

class SessionError(Exception):
    pass

@dataclass
class SessionRecord:
    key: bytes
    expiry: int
    offset: int = 0
    phone_mac: Optional[str] = None
    nonce: Optional[str] = None
    phone_hash: Optional[bytes] = None

def load_keys(lock_id: str) -> Tuple[rsa.RSAPublicKey, rsa.RSAPrivateKey]:
    with open(KEYS_DIR / "backend_public.pem", "rb") as handle:
        backend_public = cast(
            rsa.RSAPublicKey,
            load_pem_public_key(handle.read(), backend=default_backend()),
        )
    with open(KEYS_DIR / f"{lock_id}_private.pem", "rb") as handle:
        lock_private = cast(
            rsa.RSAPrivateKey,
            load_pem_private_key(handle.read(), password=None, backend=default_backend()),
        )
    return backend_public, lock_private

def _canonical_payload(payload: dict, fields: Sequence[str]) -> bytes:
    subset = {key: payload.get(key) for key in fields if key in payload}
    return json.dumps(subset, separators=(",", ":")).encode()


def extract_session(
    payload: dict,
    lock_id: str,
    backend_public: rsa.RSAPublicKey,
    lock_private: rsa.RSAPrivateKey,
) -> SessionRecord:
    signature_b64 = payload.get("signature")
    if not signature_b64:
        raise SessionError("signature missing")
    try:
        signature = base64.b64decode(signature_b64)
    except (ValueError, binascii.Error) as exc:
        raise SessionError("invalid signature encoding") from exc

    canonical = _canonical_payload(
        payload,
        ("device_id", "session_key", "expiry", "nonce", "clock_offset", "phone_mac"),
    )

    try:
        backend_public.verify(
            signature,
            canonical,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise SessionError("signature verification failed") from exc

    if payload.get("device_id") != lock_id:
        raise SessionError("device mismatch")

    encrypted_key_b64 = payload.get("session_key")
    if encrypted_key_b64 is None:
        raise SessionError("session key missing")

    try:
        encrypted_key = base64.b64decode(encrypted_key_b64)
    except (ValueError, binascii.Error) as exc:
        raise SessionError("invalid encrypted session key") from exc

    try:
        session_key = lock_private.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except ValueError as exc:
        raise SessionError("failed to decrypt session key") from exc

    try:
        expiry = int(payload["expiry"])
    except (KeyError, TypeError, ValueError) as exc:
        raise SessionError("invalid expiry") from exc

    try:
        offset_raw = payload.get("clock_offset")
        offset = int(offset_raw) if offset_raw is not None else 0
    except (TypeError, ValueError):
        offset = 0

    phone_mac = normalize_mac(payload.get("phone_mac"))
    nonce = payload.get("nonce")
    phone_hash = derive_phone_hash(phone_mac) if phone_mac else None

    return SessionRecord(
        key=session_key,
        expiry=expiry,
        offset=offset,
        phone_mac=phone_mac,
        nonce=nonce,
        phone_hash=phone_hash,
    )

def has_expired(session: SessionRecord, now: Optional[float] = None) -> bool:
    if now is None:
        now = time.time()
    return now >= session.expiry

__all__ = [
    "SessionError",
    "SessionRecord",
    "load_keys",
    "extract_session",
    "has_expired",
]

