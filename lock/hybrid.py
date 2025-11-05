import time
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple

from .core import SessionRecord, has_expired
from .protocol import (
    ACCEPT_CONN_WINDOW,
    MAX_RESPONSE_DELAY,
    AdvertisementVerification,
    ChallengePacket,
    ResponsePacket,
    build_challenge_packet,
    verify_advertisement,
    verify_response_packet,
)
from .utils import derive_phone_hash, normalize_mac


@dataclass
class PendingAdvertisement:
    session: SessionRecord
    counter: int
    time_step: int
    received_at: float
    rssi: Optional[int]


@dataclass
class ChallengeState:
    challenge: ChallengePacket
    totp_counter: int
    pending: PendingAdvertisement


class HybridAuthenticator:
    """State machine coordinating hybrid BLE authentication."""

    def __init__(self, lock_id: str):
        self.lock_id = lock_id
        self.sessions: Dict[str, SessionRecord] = {}
        self.pending: Dict[str, PendingAdvertisement] = {}
        self.challenges: Dict[str, ChallengeState] = {}
        self.replay_cache: Dict[Tuple[str, int], float] = {}
        self.session_counter: int = 0
        self.on_unlock: Optional[Callable[[str, SessionRecord], None]] = None

    def register_session(self, session: SessionRecord) -> None:
        if not session.phone_mac:
            raise ValueError("session missing phone MAC")
        mac = normalize_mac(session.phone_mac)
        if mac is None:
            raise ValueError("invalid phone MAC format")
        self.sessions[mac] = session

    def revoke_session(self, phone_mac: str) -> None:
        mac = normalize_mac(phone_mac)
        if mac is None:
            return
        self.sessions.pop(mac, None)
        self.pending.pop(mac, None)
        self.challenges.pop(mac, None)

    def _get_phone_hash(self, session: SessionRecord, device_mac: str) -> bytes:
        if session.phone_hash:
            return session.phone_hash
        if not device_mac:
            raise ValueError("phone hash unavailable")
        return derive_phone_hash(device_mac)

    def purge(self, now: Optional[float] = None) -> None:
        if now is None:
            now = time.time()
        expired_keys = [key for key, expiry in self.replay_cache.items() if expiry <= now]
        for key in expired_keys:
            self.replay_cache.pop(key, None)
        stale_pending = [mac for mac, pending in self.pending.items() if (now - pending.received_at) > ACCEPT_CONN_WINDOW]
        for mac in stale_pending:
            self.pending.pop(mac, None)
        stale_chal = [mac for mac, chal in self.challenges.items() if (now - chal.challenge.issued_at) > MAX_RESPONSE_DELAY]
        for mac in stale_chal:
            self.challenges.pop(mac, None)

    def handle_advertisement(
        self,
        device_mac: str,
        payload: bytes,
        rssi: Optional[int],
        now: Optional[float] = None,
    ) -> Optional[AdvertisementVerification]:
        mac = normalize_mac(device_mac)
        if mac is None:
            return None
        session = self.sessions.get(mac)
        if session is None:
            return None
        if has_expired(session, now):
            self.revoke_session(mac)
            return None
        phone_hash = self._get_phone_hash(session, mac)
        verification = verify_advertisement(
            payload,
            session.key,
            self.lock_id,
            phone_hash,
            now=now,
            offset=session.offset,
        )
        if verification is None:
            return None

        cache_key = (mac, verification.counter)
        cache_expiry = verification.validated_at + 2 * ACCEPT_CONN_WINDOW
        if cache_key in self.replay_cache and self.replay_cache[cache_key] > verification.validated_at:
            return None
        self.replay_cache[cache_key] = cache_expiry

        pending = PendingAdvertisement(
            session=session,
            counter=verification.counter,
            time_step=verification.frame.time_step,
            received_at=verification.validated_at,
            rssi=rssi,
        )
        self.pending[mac] = pending
        return verification

    def issue_challenge(self, device_mac: str, now: Optional[float] = None) -> ChallengePacket:
        mac = normalize_mac(device_mac)
        if mac is None:
            raise ValueError("invalid device MAC")
        pending = self.pending.get(mac)
        if pending is None:
            raise ValueError("no pending advertisement for device")
        session = pending.session
        if has_expired(session, now):
            self.revoke_session(mac)
            raise ValueError("session expired")
        current_time = time.time() if now is None else now
        if (current_time - pending.received_at) > ACCEPT_CONN_WINDOW:
            self.pending.pop(mac, None)
            raise ValueError("advertisement acceptance window elapsed")

        phone_hash = self._get_phone_hash(session, mac)
        self.session_counter = (self.session_counter + 1) & 0xFFFF
        challenge = build_challenge_packet(
            session.key,
            self.lock_id,
            phone_hash,
            pending.counter,
            self.session_counter,
            issued_at=current_time,
        )
        state = ChallengeState(challenge=challenge, totp_counter=pending.counter, pending=pending)
        self.challenges[mac] = state
        return challenge

    def verify_response(
        self,
        device_mac: str,
        payload: bytes,
        now: Optional[float] = None,
    ) -> ResponsePacket:
        mac = normalize_mac(device_mac)
        if mac is None:
            raise ValueError("invalid device MAC")
        state = self.challenges.get(mac)
        if state is None:
            raise ValueError("no challenge registered for device")
        pending = state.pending
        session = pending.session
        if has_expired(session, now):
            self.revoke_session(mac)
            raise ValueError("session expired")

        phone_hash = self._get_phone_hash(session, mac)
        response = verify_response_packet(
            payload,
            session.key,
            self.lock_id,
            phone_hash,
            state.challenge,
            state.totp_counter,
            now=now,
        )

        self.pending.pop(mac, None)
        self.challenges.pop(mac, None)
        if self.on_unlock:
            self.on_unlock(mac, session)
        return response


__all__ = ["HybridAuthenticator", "PendingAdvertisement", "ChallengeState"]
