import asyncio
import json
import logging
import os
import base64
from contextlib import suppress
from typing import Any, Dict, Optional, cast
import base64
import binascii

from bluez_peripheral.gatt.characteristic import (
	CharacteristicFlags,
	CharacteristicReadOptions,
	CharacteristicWriteOptions,
	characteristic,
)
from bluez_peripheral.gatt.service import Service
from cryptography.hazmat.primitives.asymmetric import rsa
from dbus_next.aio.message_bus import MessageBus
from dbus_next.signature import Variant

from . import config
from .keystore import KeyStore
from .session import SessionIssuer

logger = logging.getLogger(__name__)

class ProvisioningService(Service):
	exchange_char = characteristic(
		config.PROVISIONING_CHARACTERISTIC_UUID,
		CharacteristicFlags.READ
		| CharacteristicFlags.WRITE
		| CharacteristicFlags.NOTIFY,
	)

	def __init__(self, issuer: SessionIssuer, keystore: KeyStore):
		self._issuer = issuer
		self._keystore = keystore
		self._response: bytes = b""
		# Pending fragmented writes per device path
		self._pending_writes: Dict[Optional[str], Dict[str, Any]] = {}
		self._bus: Optional[MessageBus] = None
		self._loop: Optional[asyncio.AbstractEventLoop] = None
		super().__init__(config.PROVISIONING_SERVICE_UUID)

	def attach_bus(self, bus: MessageBus) -> None:
		self._bus = bus
		with suppress(RuntimeError):
			self._loop = asyncio.get_running_loop()

	@exchange_char
	def _read_exchange(self, options: CharacteristicReadOptions) -> bytes:
		return self._response

	async def _process_exchange_write(
		self,
		data: bytes,
		options: CharacteristicWriteOptions,
	) -> None:
		device_path = getattr(options, "device", None)
		# Try to interpret write as JSON. Support two modes:
		# - Single-shot JSON request
		# - Fragmented writes: JSON objects with keys {"chunk_index","total_chunks","data"}
		try:
			obj = json.loads(data.decode())
		except (UnicodeDecodeError, json.JSONDecodeError):
			logger.error("Received malformed provisioning request")
			response = {"status": "error", "message": "invalid_request"}
			self._response = json.dumps(response, separators=(",", ":")).encode()
			self.exchange_char.changed(self._response)
			return

		# Detect fragmented write
		if isinstance(obj, dict) and {"chunk_index", "total_chunks", "data"}.issubset(obj.keys()):
			device_key = device_path or "__anonymous__"
			pending = self._pending_writes.get(device_key)
			if pending is None:
				pending = {"total": int(obj["total_chunks"]), "parts": {}}
				self._pending_writes[device_key] = pending
			# store this part
			idx = int(obj["chunk_index"])
			try:
				part = base64.b64decode(obj["data"])
			except (binascii.Error, TypeError):
				logger.warning("Received invalid base64 chunk from %s", device_key)
				response = {"status": "error", "message": "invalid_chunk"}
				self._response = json.dumps(response, separators=(",", ":")).encode()
				self.exchange_char.changed(self._response)
				return
			pending["parts"][idx] = part
			# check if complete
			if len(pending["parts"]) < pending["total"]:
				# wait for more parts
				return
			# assemble
			assembled = b"".join(pending["parts"][i] for i in range(pending["total"]))
			# cleanup
			del self._pending_writes[device_key]
			# try to parse assembled as JSON request payload
			try:
				payload = json.loads(assembled.decode())
			except (UnicodeDecodeError, json.JSONDecodeError):
				logger.error("Reassembled provisioning request malformed")
				response = {"status": "error", "message": "invalid_request"}
				self._response = json.dumps(response, separators=(",", ":")).encode()
				self.exchange_char.changed(self._response)
				return
			response = await self._handle_request(payload, device_path)
		else:
			response = await self._handle_request(obj, device_path)
		# Prepare response bytes
		response_bytes = json.dumps(response, separators=(",", ":")).encode()

		# If response is large, send it as chunked notifications so BLE
		#/DBus doesn't truncate the payload on some stacks. Each notification
		# contains a small JSON object with chunk_index, total_chunks, data (base64).
		NOTIFY_CHUNK = int(os.getenv("PROVISION_NOTIFY_CHUNK_SIZE", "120"))
		if len(response_bytes) <= NOTIFY_CHUNK:
			self._response = response_bytes
			self.exchange_char.changed(self._response)
		else:
			total = (len(response_bytes) + NOTIFY_CHUNK - 1) // NOTIFY_CHUNK
			for idx in range(total):
				start = idx * NOTIFY_CHUNK
				chunk = response_bytes[start : start + NOTIFY_CHUNK]
				chunk_obj = {
					"chunk_index": idx,
					"total_chunks": total,
					"data": base64.b64encode(chunk).decode(),
				}
				self._response = json.dumps(chunk_obj, separators=(",", ":")).encode()
				self.exchange_char.changed(self._response)
				# small delay to allow the BLE stack to process notifications
				await asyncio.sleep(0.03)

	async def _resolve_device_address(self, device_path: Optional[str]) -> Optional[str]:
		if not device_path:
			return None
		bus = self._bus
		if bus is None:
			return None
		try:
			introspection = await bus.introspect("org.bluez", device_path)
			proxy = bus.get_proxy_object("org.bluez", device_path, introspection)
			props = proxy.get_interface("org.freedesktop.DBus.Properties")
			props_iface = cast(Any, props)
			address_variant = await props_iface.call_get("org.bluez.Device1", "Address")
			if isinstance(address_variant, Variant):
				return str(address_variant.value)
			return str(address_variant)
		except Exception as exc:  # pragma: no cover - best effort lookup
			logger.warning("Failed to resolve device address for %s: %s", device_path, exc)
			return None

	def _finalize_exchange_future(self, future: Any) -> None:
		try:
			future.result()
		except Exception as exc:  # pragma: no cover - background task
			logger.exception("Provisioning write task failed: %s", exc)

	@exchange_char.setter
	def _write_exchange(self, data: bytes, options: CharacteristicWriteOptions) -> None:
		coro = self._process_exchange_write(bytes(data), options)
		loop = self._loop
		if loop is None:
			try:
				loop = asyncio.get_running_loop()
			except RuntimeError:
				loop = None
		if loop is None or loop.is_closed():
			raise RuntimeError("Provisioning loop not available")
		try:
			current_loop = asyncio.get_running_loop()
		except RuntimeError:
			current_loop = None
		if current_loop is loop:
			task = loop.create_task(coro)
			task.add_done_callback(self._finalize_exchange_future)
		else:
			future = asyncio.run_coroutine_threadsafe(coro, loop)
			future.add_done_callback(self._finalize_exchange_future)

	async def _handle_request(
		self,
		payload: Dict[str, Any],
		device_path: Optional[str],
	) -> Dict[str, Any]:
		request_body = payload
		sym_key: Optional[bytes] = None
		
		if "encrypted_key" in payload:
			encryption_meta = payload.get("encryption")
			if not encryption_meta or encryption_meta.get("algorithm") != "HYBRID":
				return {"status": "error", "message": "unsupported_encryption"}
			try:
				request_body, sym_key = self._keystore.decrypt_unlocker_request(payload, encryption_meta)
			except ValueError as exc:
				logger.warning("Provisioning request decryption failed: %s", exc)
				return {"status": "error", "message": str(exc)}

		lock_id = request_body.get("lock_id")
		if not isinstance(lock_id, str) or not lock_id:
			return {"status": "error", "message": "missing_lock_id"}

		unlocker_public_key: Optional[rsa.RSAPublicKey] = None
		key_fingerprint: Optional[str] = None
		
		if "unlocker_public_key" not in request_body:
			return {"status": "error", "message": "missing_unlocker_public_key"}
		
		try:
			unlocker_public_key = self._keystore.load_unlocker_public_key_from_payload(
				request_body.get("unlocker_public_key")
			)
		except ValueError as exc:
			logger.warning("Provisioning request rejected for %s: %s", lock_id, exc)
			return {"status": "error", "message": str(exc)}
		
		key_fingerprint = self._keystore.fingerprint_public_key(unlocker_public_key)
		
		# Use fingerprint as client_id if not provided
		client_id_value = request_body.get("client_id")
		client_id = client_id_value.strip() if isinstance(client_id_value, str) else key_fingerprint

		phone_mac = request_body.get("phone_mac")
		if not phone_mac:
			phone_mac = await self._resolve_device_address(device_path)
		client_time = request_body.get("client_time")

		try:
			result = await asyncio.to_thread(
				self._issuer.issue_session,
				lock_id,
				phone_mac=phone_mac,
				client_id=client_id,
				client_time=client_time,
				unlocker_public_key=unlocker_public_key,
			)
		except ValueError as exc:
			logger.warning("Provisioning request rejected for %s: %s", lock_id, exc)
			return {"status": "error", "message": str(exc)}
		except Exception:
			logger.exception("Provisioning request failed for %s", lock_id)
			return {"status": "error", "message": "internal_error"}

		extra: Dict[str, Any] = {"client_id": client_id}
		if key_fingerprint and key_fingerprint != client_id:
			extra["key_fingerprint"] = key_fingerprint
		response = {"status": "ok", **extra, **result}
		
		# If client sent a symmetric key, encrypt the response with it
		if sym_key:
			response = self._keystore.encrypt_response_with_symmetric_key(response, sym_key)
		
		return response
