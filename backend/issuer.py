from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

if __package__ is None or __package__ == "":  # pragma: no cover - script invocation support
	sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend import config
from backend.beacon import IssuerBeaconAdvertiser
from backend.keystore import KeyStore
from backend.session import SessionIssuer

logger = logging.getLogger(__name__)

def main() -> None:
	logging.basicConfig(
		level=getattr(logging, config.DEFAULT_LOGGING_LEVEL.upper(), logging.INFO),
		format=config.DEFAULT_LOGGING_FORMAT,
	)

	keystore = KeyStore()
	session_issuer = SessionIssuer(keystore)
	beacon_thread = IssuerBeaconAdvertiser(session_issuer, keystore)
	beacon_thread.start()
	logger.info("Issuer beacon ready; press Ctrl+C to stop")
	try:
		while True:
			time.sleep(1)
	except KeyboardInterrupt:
		logger.info("Script stopped by user.")
	except Exception as exc:  # pragma: no cover - defensive logging
		logger.exception("Unhandled error in backend issuer: %s", exc)
	finally:
		beacon_thread.stop()

if __name__ == "__main__":
	main()
