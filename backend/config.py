import os
from pathlib import Path
from typing import List

ROOT_DIR = Path(__file__).resolve().parent.parent
_DEFAULT_KEYS_DIR = ROOT_DIR / "keys"
KEYS_DIR = Path(os.getenv("KEYS_DIR", str(_DEFAULT_KEYS_DIR)))

MQTT_BROKER = os.getenv("MQTT_BROKER", "127.0.0.1")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
SESSION_EXPIRY_SECONDS = int(os.getenv("SESSION_EXPIRY_SECONDS", "300"))

PROVISIONING_SERVICE_UUID = os.getenv(
	"PROVISIONING_SERVICE_UUID",
	"c0de0001-0000-1000-8000-00805f9b34fb",
)
PROVISIONING_CHARACTERISTIC_UUID = os.getenv(
	"PROVISIONING_CHARACTERISTIC_UUID",
	"c0de0002-0000-1000-8000-00805f9b34fb",
)

ISSUER_BEACON_NAME = os.getenv("ISSUER_BEACON_NAME", "IssuerBeacon")
_SERVICE_UUIDS_ENV = os.getenv("ISSUER_SERVICE_UUIDS", "180D")
ISSUER_SERVICE_UUIDS: List[str] = [
	uuid.strip() for uuid in _SERVICE_UUIDS_ENV.split(",") if uuid.strip()
]
ISSUER_MANUFACTURER_ID = int(os.getenv("ISSUER_MANUFACTURER_ID", str(0xFFFF)))
ISSUER_ADVERT_PATH = os.getenv("ISSUER_ADVERT_PATH", "/com/ble_lock/issuer/advert0")
ISSUER_ADVERT_TIMEOUT = int(os.getenv("ISSUER_ADVERT_TIMEOUT", "0"))
ISSUER_BEACON_APPEARANCE = int(os.getenv("ISSUER_BEACON_APPEARANCE", str(0x0340)))
ISSUER_BEACON_MIN_INTERVAL = int(os.getenv("ISSUER_BEACON_MIN_INTERVAL", "100"))
ISSUER_BEACON_MAX_INTERVAL = int(os.getenv("ISSUER_BEACON_MAX_INTERVAL", "200"))

DEFAULT_LOGGING_FORMAT = os.getenv("ISSUER_LOG_FORMAT", "[%(levelname)s] %(message)s")
DEFAULT_LOGGING_LEVEL = os.getenv("ISSUER_LOG_LEVEL", "INFO")
