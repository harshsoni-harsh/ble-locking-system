import asyncio
import base64
import json
import logging
from typing import Dict, Optional

import paho.mqtt.client as mqtt
from bleak import BleakScanner
from paho.mqtt.enums import CallbackAPIVersion

from lock.core import (
    MANUFACTURER_ID,
    SessionError,
    SessionRecord,
    extract_session,
    has_expired,
    load_keys,
    normalize_mac,
    validate_token,
)

MQTT_BROKER = "10.0.10.142"
MQTT_PORT = 1883
LOCK_ID = "lock_01"
DEFAULT_RSSI_THRESHOLD = -70

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

AUTHORIZED_PHONES: Dict[str, Dict[str, int]] = {
    # "AA:BB:CC:DD:EE:FF": {"rssi_threshold": -68},
}

BACKEND_PUBLIC_KEY, LOCK_PRIVATE_KEY = load_keys(LOCK_ID)

SESSIONS: Dict[str, SessionRecord] = {}

def on_message(client, userdata, msg):
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

    phone_mac = session.phone_mac
    if not phone_mac:
        logger.error("Payload missing phone MAC; ignoring")
        return

    if phone_mac not in AUTHORIZED_PHONES:
        logger.warning("Unauthorized phone %s; ignoring", phone_mac)
        return

    SESSIONS[phone_mac] = session
    key_b64 = base64.b64encode(session.key).decode()
    logger.info(
        "Stored session for %s: key=%s expires=%s nonce=%s offset=%s",
        phone_mac,
        key_b64,
        session.expiry,
        session.nonce,
        session.offset,
    )

def detection_callback(device, advertisement_data):
    device_mac = normalize_mac(device.address)
    if not device_mac:
        return

    session = SESSIONS.get(device_mac)
    if session is None:
        return

    entry = AUTHORIZED_PHONES.get(device_mac, {})
    threshold = entry.get("rssi_threshold", DEFAULT_RSSI_THRESHOLD)
    rssi = advertisement_data.rssi
    if rssi is not None and rssi <= threshold:
        logger.info(
            "Device %s too far (RSSI %s <= %s); ignoring",
            device_mac,
            rssi,
            threshold,
        )
        return

    token_sources = advertisement_data.manufacturer_data or {}
    token = token_sources.get(MANUFACTURER_ID)
    if not token:
        return

    if has_expired(session):
        logger.warning(
            "Session for %s expired at %s; dropping",
            device_mac,
            session.expiry,
        )
        SESSIONS.pop(device_mac, None)
        return

    if validate_token(token, session):
        logger.info("Token valid for %s; unlocking", device_mac)
    else:
        logger.warning("Invalid token from %s: %s", device_mac, token.hex())

async def main():
    client = mqtt.Client(callback_api_version=CallbackAPIVersion.VERSION2)
    client.on_message = on_message
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    topic = f"locks/{LOCK_ID}/session"
    client.subscribe(topic)
    client.loop_start()
    logger.info("Subscribed to %s for session keys", topic)

    scanner = BleakScanner(detection_callback=detection_callback)
    await scanner.start()
    logger.info("BLE scanner started")

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping...")
    finally:
        client.loop_stop()
        client.disconnect()
        await scanner.stop()


if __name__ == "__main__":
    asyncio.run(main())
