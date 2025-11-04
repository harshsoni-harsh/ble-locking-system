import asyncio
import base64
import json
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

MQTT_BROKER = "10.0.15.108"
MQTT_PORT = 1883
LOCK_ID = "lock_01"
DEFAULT_RSSI_THRESHOLD = -70

AUTHORIZED_PHONES: Dict[str, Dict[str, int]] = {
    # "AA:BB:CC:DD:EE:FF": {"rssi_threshold": -68},
}

BACKEND_PUBLIC_KEY, LOCK_PRIVATE_KEY = load_keys(LOCK_ID)

SESSIONS: Dict[str, SessionRecord] = {}


def on_message(client, userdata, msg):
    print(f"Received request on {msg.topic}")
    try:
        payload = json.loads(msg.payload.decode())
    except json.JSONDecodeError:
        print("Malformed JSON payload; ignoring")
        return

    try:
        session = extract_session(payload, LOCK_ID, BACKEND_PUBLIC_KEY, LOCK_PRIVATE_KEY)
    except SessionError as exc:
        print(f"Invalid session payload: {exc}")
        return

    phone_mac = session.phone_mac
    if not phone_mac:
        print("Payload missing phone MAC; ignoring")
        return

    if phone_mac not in AUTHORIZED_PHONES:
        print(f"Unauthorized phone {phone_mac}; ignoring")
        return

    SESSIONS[phone_mac] = session
    key_b64 = base64.b64encode(session.key).decode()
    print(
        f"Stored session for {phone_mac}: key={key_b64} expires={session.expiry} nonce={session.nonce} offset={session.offset}"
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
        print(f"Device {device_mac} too far (RSSI {rssi} <= {threshold}); ignoring")
        return

    token_sources = advertisement_data.manufacturer_data or {}
    token = token_sources.get(MANUFACTURER_ID)
    if not token:
        return

    if has_expired(session):
        print(f"Session for {device_mac} expired at {session.expiry}; dropping")
        SESSIONS.pop(device_mac, None)
        return

    if validate_token(token, session):
        print(f"Token valid for {device_mac}! Unlocking...")
    else:
        print(f"Invalid token from {device_mac}: {token.hex()}")


async def main():
    client = mqtt.Client(callback_api_version=CallbackAPIVersion.VERSION2)
    client.on_message = on_message
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    topic = f"locks/{LOCK_ID}/session"
    client.subscribe(topic)
    client.loop_start()
    print(f"Subscribed to {topic} for session keys")

    scanner = BleakScanner(detection_callback=detection_callback)
    await scanner.start()
    print("BLE scanner started")

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("Stopping...")
    finally:
        client.loop_stop()
        client.disconnect()
        await scanner.stop()


if __name__ == "__main__":
    asyncio.run(main())
