import hashlib
from typing import Optional

__all__ = ["normalize_mac", "derive_phone_hash", "short_lock_id", "derive_key_material"]


def normalize_mac(value: Optional[str]) -> Optional[str]:
    """Normalize a MAC address string to uppercase colon separated form."""
    if not value:
        return None
    text = str(value).strip().upper().replace("-", ":")
    if ":" not in text:
        # Accept BlueZ style underscores as used in D-Bus paths.
        text = text.replace("_", ":")
    return text


def derive_phone_hash(identifier: str, length: int = 4) -> bytes:
    """Return a truncated SHA-256 hash for the given phone identifier.

    Parameters
    ----------
    identifier: str
        Unique identifier for the phone (e.g. BLE MAC, UUID).
    length: int
        Number of bytes to keep from the hash.
    """
    digest = hashlib.sha256(identifier.encode("utf-8")).digest()
    return digest[:length]


def short_lock_id(lock_id: str, length: int = 2) -> bytes:
    """Return a shortened identifier for the lock usable in BLE payloads."""
    digest = hashlib.sha256(lock_id.encode("utf-8")).digest()
    return digest[:length]


def derive_key_material(shared_key: bytes, salt: bytes, length: int) -> bytes:
    """Derive deterministic key material from the shared secret.

    This uses SHA-256 in counter mode to avoid pulling in HKDF for short keys.
    """
    counter = 0
    output = bytearray()
    while len(output) < length:
        counter_bytes = counter.to_bytes(4, "big")
        output.extend(hashlib.sha256(shared_key + salt + counter_bytes).digest())
        counter += 1
    return bytes(output[:length])
