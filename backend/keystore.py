import os
import base64
import binascii
import hashlib
import json
from contextlib import suppress
from pathlib import Path
from typing import Any, Dict, Optional, cast

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
	Encoding,
	PublicFormat,
	load_pem_private_key,
	load_pem_public_key,
)

from . import config

class KeyStore:
	"""Handles key material for the issuer and known devices."""

	def __init__(self, keys_dir: Optional[Path] = None):
		self._keys_dir = keys_dir or config.KEYS_DIR
		self._backend_private_key = self._load_backend_private_key()
		self._backend_public_key = self._backend_private_key.public_key()
		self._lock_public_keys = self._discover_lock_public_keys()
		self._unlocker_public_keys = self._discover_unlocker_public_keys()

	def _load_backend_private_key(self) -> rsa.RSAPrivateKey:
		path = self._keys_dir / "backend_private.pem"
		with open(path, "rb") as handle:
			return cast(
				rsa.RSAPrivateKey,
				load_pem_private_key(handle.read(), password=None, backend=default_backend()),
			)

	def _discover_lock_public_keys(self) -> Dict[str, Path]:
		result: Dict[str, Path] = {}
		for candidate in self._keys_dir.glob("*_public.pem"):
			stem = candidate.stem.replace("_public", "")
			if stem.startswith("unlocker") or stem == "backend":
				continue
			result[stem] = candidate
		return result

	def _discover_unlocker_public_keys(self) -> Dict[str, Path]:
		result: Dict[str, Path] = {}
		default_key = self._keys_dir / "unlocker_public.pem"
		if default_key.exists():
			result["default"] = default_key
		for candidate in self._keys_dir.glob("unlocker_*_public.pem"):
			identifier = candidate.stem.replace("_public", "")
			if identifier.startswith("unlocker_"):
				identifier = identifier[len("unlocker_") :]
			result[identifier] = candidate
		return result

	@property
	def backend_private_key(self) -> rsa.RSAPrivateKey:
		return self._backend_private_key

	@property
	def backend_public_key(self) -> rsa.RSAPublicKey:
		return self._backend_public_key

	@property
	def backend_public_key_pem(self) -> bytes:
		return self._backend_public_key.public_bytes(
			encoding=Encoding.PEM,
			format=PublicFormat.SubjectPublicKeyInfo,
		)

	@property
	def backend_public_key_der(self) -> bytes:
		return self._backend_public_key.public_bytes(
			encoding=Encoding.DER,
			format=PublicFormat.SubjectPublicKeyInfo,
		)

	def load_lock_public_key(self, device_id: str) -> rsa.RSAPublicKey:
		key_path = self._lock_public_keys.get(device_id)
		if key_path is None or not key_path.exists():
			raise ValueError(f"Unknown lock id {device_id}")
		with open(key_path, "rb") as handle:
			return cast(
				rsa.RSAPublicKey,
				load_pem_public_key(handle.read(), backend=default_backend()),
			)

	def has_lock(self, device_id: str) -> bool:
		return device_id in self._lock_public_keys

	def load_unlocker_public_key(self, client_id: str) -> rsa.RSAPublicKey:
		key_path = self._unlocker_public_keys.get(client_id)
		if key_path is None:
			key_path = self._unlocker_public_keys.get("default")
		if key_path is None or not key_path.exists():
			raise ValueError(f"Unknown client id {client_id}")
		with open(key_path, "rb") as handle:
			return cast(
				rsa.RSAPublicKey,
				load_pem_public_key(handle.read(), backend=default_backend()),
			)

	def load_unlocker_public_key_from_payload(self, value: Any) -> rsa.RSAPublicKey:
		if not isinstance(value, str) or not value:
			raise ValueError("missing unlocker_public_key")
		candidates = []
		with suppress(binascii.Error, TypeError):
			decoded = base64.b64decode(value)
			candidates.append(decoded)
		candidates.append(value.encode())
		for candidate in candidates:
			try:
				return cast(
					rsa.RSAPublicKey,
					load_pem_public_key(candidate, backend=default_backend()),
				)
			except ValueError:
				continue
		raise ValueError("unable to parse unlocker public key")

	def encrypt_for_lock(self, session_key: bytes, device_id: str) -> bytes:
		pubkey = self.load_lock_public_key(device_id)
		return pubkey.encrypt(
			session_key,
			padding.OAEP(
				mgf=padding.MGF1(algorithm=hashes.SHA256()),
				algorithm=hashes.SHA256(),
				label=None,
			),
		)

	def encrypt_for_unlocker(
		self,
		payload: bytes,
		*,
		client_id: Optional[str] = None,
		public_key: Optional[rsa.RSAPublicKey] = None,
	) -> bytes:
		pubkey = public_key
		if pubkey is None:
			if not client_id:
				raise ValueError("missing unlocker encryption key")
			pubkey = self.load_unlocker_public_key(client_id)
		return pubkey.encrypt(
			payload,
			padding.OAEP(
				mgf=padding.MGF1(algorithm=hashes.SHA256()),
				algorithm=hashes.SHA256(),
				label=None,
			),
		)

	def decrypt_unlocker_request(self, payload: Any, encryption_meta: Optional[Dict[str, Any]] = None) -> tuple[Dict[str, Any], Optional[bytes]]:
		"""Decrypt a provisioning request from an unlocker.
		
		Expects HYBRID format: payload contains 'request' (plaintext dict) and 
		'encrypted_key' (RSA-OAEP encrypted symmetric key for response encryption).
		
		Returns: tuple of (request_dict, symmetric_key_bytes or None)
		"""
		if not isinstance(payload, dict):
			raise ValueError("invalid payload format - expected dict")

		algo = (encryption_meta or {}).get("algorithm") if isinstance(encryption_meta, dict) else None
		if algo != "HYBRID":
			raise ValueError(f"unsupported encryption algorithm: {algo}")

		# HYBRID format: plaintext request + RSA-encrypted symmetric key
		encrypted_key_b64 = payload.get("encrypted_key")
		if not isinstance(encrypted_key_b64, str) or not encrypted_key_b64:
			raise ValueError("missing encrypted_key")
		
		try:
			encrypted_key = base64.b64decode(encrypted_key_b64)
		except (binascii.Error, TypeError) as exc:
			raise ValueError("invalid encrypted_key encoding") from exc
		
		try:
			sym_key = self.backend_private_key.decrypt(
				encrypted_key,
				padding.OAEP(
					mgf=padding.MGF1(algorithm=hashes.SHA256()),
					algorithm=hashes.SHA256(),
					label=None,
				),
			)
		except Exception as exc:
			raise ValueError("failed to decrypt symmetric key") from exc
		
		# Extract plaintext request
		request_obj = payload.get("request")
		if not isinstance(request_obj, dict):
			raise ValueError("missing or invalid request object")
		
		return request_obj, sym_key

	def encrypt_response_with_symmetric_key(self, response_data: Dict[str, Any], sym_key: bytes) -> Dict[str, Any]:
		"""Encrypt a response using AES-GCM with the provided symmetric key.
		
		Returns a dict with 'ciphertext' (base64 nonce+ciphertext) and 'encryption' metadata.
		"""
		plaintext = json.dumps(response_data, separators=(",", ":")).encode()
		aesgcm = AESGCM(sym_key)
		nonce = os.urandom(12)
		ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
		return {
			"ciphertext": base64.b64encode(nonce + ciphertext).decode(),
			"encryption": {"algorithm": "HYBRID", "symmetric": "AES-GCM"},
		}

	def sign_payload(self, payload: bytes) -> str:
		signature = self.backend_private_key.sign(
			payload,
			padding.PSS(
				mgf=padding.MGF1(hashes.SHA256()),
				salt_length=padding.PSS.MAX_LENGTH,
			),
			hashes.SHA256(),
		)
		return base64.b64encode(signature).decode()

	@staticmethod
	def fingerprint_public_key(public_key: rsa.RSAPublicKey) -> str:
		der_bytes = public_key.public_bytes(
			encoding=Encoding.DER,
			format=PublicFormat.SubjectPublicKeyInfo,
		)
		digest = hashlib.sha256(der_bytes).digest()
		return base64.urlsafe_b64encode(digest[:10]).decode().rstrip("=")
