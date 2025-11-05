import hashlib
import hmac
import secrets
import struct
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms

from .utils import derive_key_material, derive_phone_hash, short_lock_id

PROTOCOL_VERSION = 1
TOTP_STEP_SECONDS = 30
ADV_PAYLOAD_VERSION = PROTOCOL_VERSION
ADV_WINDOW_STEPS = 1
ADV_MAC_LENGTH = 4
TOTP_LENGTH = 10
CHALLENGE_NONCE_LEN = 12
CHALLENGE_MAC_LEN = 8
RESPONSE_MAC_LEN = 16
ACCEPT_CONN_WINDOW = 5.0  # seconds
MAX_RESPONSE_DELAY = 0.75  # seconds
CLOCK_SKEW_TOLERANCE = 2  # seconds

_ADV_HEADER_STRUCT = struct.Struct("<B H")
_ADV_BODY_PREFIX = struct.Struct("<4sB")
_ADV_TOTAL_LEN = _ADV_HEADER_STRUCT.size + _ADV_BODY_PREFIX.size + TOTP_LENGTH + ADV_MAC_LENGTH
_CHALLENGE_STRUCT = struct.Struct(f"<12sIH{CHALLENGE_MAC_LEN}s")
_RESPONSE_STRUCT = struct.Struct(f"<IB{RESPONSE_MAC_LEN}s")


@dataclass
class AdvertisementFrame:
    proto_version: int
    lock_short_id: int
    phone_hash: bytes
    time_counter: int
    totp: bytes
    mac: bytes
    timestamp: float

    @property
    def time_step(self) -> int:
        return self.time_counter & 0xFF

    def encode(self) -> bytes:
        header = _ADV_HEADER_STRUCT.pack(self.proto_version, self.lock_short_id)
        body = _ADV_BODY_PREFIX.pack(self.phone_hash, self.time_step) + self.totp
        return header + body + self.mac


@dataclass
class AdvertisementVerification:
    frame: AdvertisementFrame
    counter: int
    validated_at: float


@dataclass
class ChallengePacket:
    nonce: bytes
    lock_timestamp: int
    session_id: int
    mac: bytes
    issued_at: float
    totp_counter: int

    def encode(self) -> bytes:
        return _CHALLENGE_STRUCT.pack(self.nonce, self.lock_timestamp, self.session_id, self.mac)


@dataclass
class ResponsePacket:
    phone_timestamp: int
    time_step: int
    mac: bytes

    def encode(self) -> bytes:
        return _RESPONSE_STRUCT.pack(self.phone_timestamp, self.time_step, self.mac)


def _cmac(key: bytes, payload: bytes) -> bytes:
    cmac = CMAC(algorithms.AES(key), backend=default_backend())
    cmac.update(payload)
    return cmac.finalize()


def _totp_digest(shared_key: bytes, lock_id: str, phone_hash: bytes, counter: int) -> bytes:
    msg = lock_id.encode("utf-8") + phone_hash + counter.to_bytes(8, "big")
    return hmac.new(shared_key, msg, hashlib.sha256).digest()


def build_advertisement_frame(
    shared_key: bytes,
    lock_id: str,
    phone_identifier: str,
    now: Optional[float] = None,
) -> AdvertisementFrame:
    if now is None:
        now = time.time()
    counter = int(now // TOTP_STEP_SECONDS)
    phone_hash = derive_phone_hash(phone_identifier)
    lock_short = int.from_bytes(short_lock_id(lock_id), "little")

    totp_full = _totp_digest(shared_key, lock_id, phone_hash, counter)
    totp = totp_full[:TOTP_LENGTH]

    header = _ADV_HEADER_STRUCT.pack(ADV_PAYLOAD_VERSION, lock_short)
    body = _ADV_BODY_PREFIX.pack(phone_hash, counter & 0xFF) + totp
    adv_mac_key = derive_key_material(shared_key, b"adv-mac", 16)
    mac = _cmac(adv_mac_key, header + body)[:ADV_MAC_LENGTH]

    return AdvertisementFrame(
        proto_version=ADV_PAYLOAD_VERSION,
        lock_short_id=lock_short,
        phone_hash=phone_hash,
        time_counter=counter,
        totp=totp,
        mac=mac,
        timestamp=now,
    )


def decode_advertisement_payload(payload: bytes) -> AdvertisementFrame:
    if len(payload) != _ADV_TOTAL_LEN:
        raise ValueError("unexpected advertisement payload length")
    header = payload[: _ADV_HEADER_STRUCT.size]
    body = payload[_ADV_HEADER_STRUCT.size : _ADV_HEADER_STRUCT.size + _ADV_BODY_PREFIX.size + TOTP_LENGTH]
    mac = payload[-ADV_MAC_LENGTH:]

    proto_version, lock_short = _ADV_HEADER_STRUCT.unpack(header)
    phone_hash, time_step = _ADV_BODY_PREFIX.unpack(body[: _ADV_BODY_PREFIX.size])
    totp = body[_ADV_BODY_PREFIX.size :]

    frame = AdvertisementFrame(
        proto_version=proto_version,
        lock_short_id=lock_short,
        phone_hash=phone_hash,
        time_counter=time_step,
        totp=totp,
        mac=mac,
        timestamp=time.time(),
    )
    return frame


def verify_advertisement(
    payload: bytes,
    shared_key: bytes,
    lock_id: str,
    expected_phone_hash: bytes,
    now: Optional[float] = None,
    offset: int = 0,
    window: int = ADV_WINDOW_STEPS,
) -> Optional[AdvertisementVerification]:
    if now is None:
        now = time.time()

    if len(payload) != _ADV_TOTAL_LEN:
        return None

    proto_version, lock_short = _ADV_HEADER_STRUCT.unpack(payload[: _ADV_HEADER_STRUCT.size])
    if proto_version != ADV_PAYLOAD_VERSION:
        return None

    expected_short = int.from_bytes(short_lock_id(lock_id), "little")
    if lock_short != expected_short:
        return None

    phone_hash, time_step = _ADV_BODY_PREFIX.unpack(
        payload[_ADV_HEADER_STRUCT.size : _ADV_HEADER_STRUCT.size + _ADV_BODY_PREFIX.size]
    )
    if phone_hash != expected_phone_hash:
        return None

    totp = payload[
        _ADV_HEADER_STRUCT.size + _ADV_BODY_PREFIX.size : _ADV_HEADER_STRUCT.size + _ADV_BODY_PREFIX.size + TOTP_LENGTH
    ]
    mac = payload[-ADV_MAC_LENGTH:]

    adv_mac_key = derive_key_material(shared_key, b"adv-mac", 16)
    header = payload[: _ADV_HEADER_STRUCT.size]
    body = payload[_ADV_HEADER_STRUCT.size : -ADV_MAC_LENGTH]
    if not hmac.compare_digest(_cmac(adv_mac_key, header + body)[:ADV_MAC_LENGTH], mac):
        return None

    base_counter = int((now + offset) // TOTP_STEP_SECONDS)

    for delta in range(-window, window + 1):
        candidate = base_counter + delta
        digest = _totp_digest(shared_key, lock_id, phone_hash, candidate)[:TOTP_LENGTH]
        if digest == totp and (candidate & 0xFF) == time_step:
            frame = AdvertisementFrame(
                proto_version=proto_version,
                lock_short_id=lock_short,
                phone_hash=phone_hash,
                time_counter=candidate,
                totp=totp,
                mac=mac,
                timestamp=now,
            )
            return AdvertisementVerification(frame=frame, counter=candidate, validated_at=now)
    return None


def build_challenge_packet(
    shared_key: bytes,
    lock_id: str,
    phone_hash: bytes,
    totp_counter: int,
    session_counter: int,
    issued_at: Optional[float] = None,
) -> ChallengePacket:
    if issued_at is None:
        issued_at = time.time()
    nonce = secrets.token_bytes(CHALLENGE_NONCE_LEN)
    lock_ts = int(issued_at)
    session_id = session_counter & 0xFFFF
    context = short_lock_id(lock_id) + phone_hash
    chal_mac_key = derive_key_material(shared_key, b"chal-mac", 16)
    mac_body = context + nonce + lock_ts.to_bytes(4, "little") + session_id.to_bytes(2, "little")
    mac = _cmac(chal_mac_key, mac_body)[:CHALLENGE_MAC_LEN]
    return ChallengePacket(
        nonce=nonce,
        lock_timestamp=lock_ts,
        session_id=session_id,
        mac=mac,
        issued_at=issued_at,
        totp_counter=totp_counter,
    )


def verify_challenge_packet(
    payload: bytes,
    shared_key: bytes,
    lock_id: str,
    phone_identifier: str,
) -> ChallengePacket:
    if len(payload) != _CHALLENGE_STRUCT.size:
        raise ValueError("challenge payload length mismatch")

    nonce, lock_ts, session_id, mac = _CHALLENGE_STRUCT.unpack(payload)
    phone_hash = derive_phone_hash(phone_identifier)
    context = short_lock_id(lock_id) + phone_hash
    chal_mac_key = derive_key_material(shared_key, b"chal-mac", 16)
    mac_body = context + nonce + lock_ts.to_bytes(4, "little") + session_id.to_bytes(2, "little")
    if not hmac.compare_digest(_cmac(chal_mac_key, mac_body)[:CHALLENGE_MAC_LEN], mac):
        raise ValueError("challenge MAC validation failed")
    return ChallengePacket(
        nonce=nonce,
        lock_timestamp=lock_ts,
        session_id=session_id,
        mac=mac,
        issued_at=time.time(),
        totp_counter=0,
    )


def build_response_packet(
    shared_key: bytes,
    lock_id: str,
    phone_hash: bytes,
    challenge: ChallengePacket,
    totp_counter: int,
    now: Optional[float] = None,
) -> ResponsePacket:
    if now is None:
        now = time.time()
    phone_ts = int(now)
    time_step = totp_counter & 0xFF
    context = short_lock_id(lock_id) + phone_hash
    response_key = derive_key_material(shared_key, b"resp-mac", 32)
    mac_body = (
        context
        + challenge.nonce
        + challenge.lock_timestamp.to_bytes(4, "little")
        + challenge.session_id.to_bytes(2, "little")
        + phone_ts.to_bytes(4, "little")
        + bytes([time_step])
    )
    mac = hmac.new(response_key, mac_body, hashlib.sha256).digest()[:RESPONSE_MAC_LEN]
    return ResponsePacket(phone_timestamp=phone_ts, time_step=time_step, mac=mac)


def verify_response_packet(
    payload: bytes,
    shared_key: bytes,
    lock_id: str,
    phone_hash: bytes,
    challenge: ChallengePacket,
    expected_totp_counter: int,
    now: Optional[float] = None,
    max_skew: int = CLOCK_SKEW_TOLERANCE,
    max_delay: float = MAX_RESPONSE_DELAY,
) -> ResponsePacket:
    if len(payload) != _RESPONSE_STRUCT.size:
        raise ValueError("response payload length mismatch")
    phone_ts, time_step, mac = _RESPONSE_STRUCT.unpack(payload)
    if now is None:
        now = time.time()

    if abs(phone_ts - challenge.lock_timestamp) > max_skew:
        raise ValueError("clock skew exceeds tolerance")

    if (now - challenge.issued_at) > max_delay:
        raise ValueError("response timed out")

    expected_step = expected_totp_counter & 0xFF
    if time_step != expected_step:
        raise ValueError("TOTP step mismatch")

    context = short_lock_id(lock_id) + phone_hash
    response_key = derive_key_material(shared_key, b"resp-mac", 32)
    mac_body = (
        context
        + challenge.nonce
        + challenge.lock_timestamp.to_bytes(4, "little")
        + challenge.session_id.to_bytes(2, "little")
        + phone_ts.to_bytes(4, "little")
        + bytes([time_step])
    )
    expected_mac = hmac.new(response_key, mac_body, hashlib.sha256).digest()[:RESPONSE_MAC_LEN]
    if not hmac.compare_digest(expected_mac, mac):
        raise ValueError("response MAC validation failed")

    return ResponsePacket(phone_timestamp=phone_ts, time_step=time_step, mac=mac)


__all__ = [
    "AdvertisementFrame",
    "AdvertisementVerification",
    "ChallengePacket",
    "ResponsePacket",
    "build_advertisement_frame",
    "decode_advertisement_payload",
    "verify_advertisement",
    "build_challenge_packet",
    "verify_challenge_packet",
    "build_response_packet",
    "verify_response_packet",
    "ACCEPT_CONN_WINDOW",
    "MAX_RESPONSE_DELAY",
    "CLOCK_SKEW_TOLERANCE",
    "TOTP_STEP_SECONDS",
]
