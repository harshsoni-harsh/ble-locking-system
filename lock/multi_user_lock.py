import asyncio
import base64
import json
import logging
import sys
import time
from pathlib import Path
from typing import Dict

import paho.mqtt.client as mqtt
from bleak import BleakScanner
from paho.mqtt.enums import CallbackAPIVersion

if __package__ is None or __package__ == "":  # pragma: no cover - script execution support
    sys.path.append(str(Path(__file__).resolve().parent.parent))
    __package__ = "lock"

from .auth_service import register_auth_service, unregister_auth_service
from .constants import MANUFACTURER_ID
from .core import SessionError, extract_session, load_keys
from .hybrid import HybridAuthenticator
from .utils import normalize_mac

MQTT_BROKER = "0.0.0.0"
MQTT_PORT = 1883
LOCK_ID = "lock_01"
DEFAULT_RSSI_THRESHOLD = -70

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

AUTHORIZED_PHONES: Dict[str, Dict[str, int]] = {
    # "AA:BB:CC:DD:EE:FF": {"rssi_threshold": -68},
}

BACKEND_PUBLIC_KEY, LOCK_PRIVATE_KEY = load_keys(LOCK_ID)
AUTHENTICATOR = HybridAuthenticator(LOCK_ID)


def _authorized(mac: str) -> bool:
    return mac in AUTHORIZED_PHONES


def _unlock_callback(mac: str, _session) -> None:
    logger.info("Unlock granted to %s", mac)


AUTHENTICATOR.on_unlock = _unlock_callback


def on_message(client, _userdata, msg):
    logger.info("Received request on %s", msg.topic)
    try:
        payload = json.loads(msg.payload.decode())
    except json.JSONDecodeError:
        logger.error("Malformed JSON payload; ignoring")
        return

    try:
        session = extract_session(payload, LOCK_ID, BACKEND_PUBLIC_KEY, LOCK_PRIVATE_KEY)
    except SessionError as exc:
        logger.error("Invalid session payload: %s", exc)
        return

    mac = normalize_mac(session.phone_mac)
    if not mac or not _authorized(mac):
        logger.warning("Unauthorized phone %s; ignoring", session.phone_mac)
        return

    try:
        AUTHENTICATOR.register_session(session)
    except ValueError as exc:
        logger.error("Failed to register session: %s", exc)
        return

    key_b64 = base64.b64encode(session.key).decode()
    logger.info(
        "Stored session for %s key=%s expires=%s",
        mac,
        key_b64,
        session.expiry,
    )


def detection_callback(device, advertisement_data):
    mac = normalize_mac(device.address)
    if not mac or not _authorized(mac):
        return

    entry = AUTHORIZED_PHONES.get(mac, {})
    threshold = entry.get("rssi_threshold", DEFAULT_RSSI_THRESHOLD)
    rssi = advertisement_data.rssi
    if rssi is not None and rssi <= threshold:
        logger.debug(
            "Device %s too far (RSSI %s <= %s)",
            mac,
            rssi,
            threshold,
        )
        return

    payload_map = advertisement_data.manufacturer_data or {}
    payload = payload_map.get(MANUFACTURER_ID)
    if not payload:
        return

    verification = AUTHENTICATOR.handle_advertisement(
        mac,
        bytes(payload),
        rssi,
        now=time.time(),
    )
    if verification:
        logger.info(
            "Advertisement accepted from %s (step=0x%02X)",
            mac,
            verification.frame.time_step,
        )


async def setup_mqtt() -> mqtt.Client:
    client = mqtt.Client(callback_api_version=CallbackAPIVersion.VERSION2)
    client.on_message = on_message
    try:
        client.connect(MQTT_BROKER, MQTT_PORT, 60)
    except OSError as exc:
        raise ConnectionError(
            f"Failed to connect to MQTT broker at {MQTT_BROKER}:{MQTT_PORT}: {exc}"
        ) from exc
    topic = f"locks/{LOCK_ID}/session"
    client.subscribe(topic)
    client.loop_start()
    logger.info("Subscribed to %s for session keys", topic)
    return client


async def main():
    try:
        client = await setup_mqtt()
    except ConnectionError as exc:
        logger.error("Unable to connect to MQTT broker: %s", exc)
        return

    try:
        service, bus, adapter = await register_auth_service(AUTHENTICATOR)
    except RuntimeError as exc:
        logger.error("Unable to register BLE GATT service: %s", exc)
        client.loop_stop()
        client.disconnect()
        return

    scanner = BleakScanner(detection_callback=detection_callback)
    try:
        await scanner.start()
    except Exception as exc:
        logger.error("Failed to start BLE scanner: %s", exc)
        await unregister_auth_service(service, bus, adapter)
        client.loop_stop()
        client.disconnect()
        return

    logger.info("BLE scanner started")

    try:
        while True:
            AUTHENTICATOR.purge()
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping...")
    finally:
        client.loop_stop()
        client.disconnect()
        await scanner.stop()
        await unregister_auth_service(service, bus, adapter)


if __name__ == "__main__":
    asyncio.run(main())
