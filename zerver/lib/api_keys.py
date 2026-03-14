import base64
import binascii
import functools
import hashlib
import hmac
import logging
import os
import types
from typing import Final

from django.conf import settings

from zerver import models
from zerver.lib import crypto


API_KEY_HASH_PREFIX: Final[str] = "h1"
API_KEY_HASH_LENGTH: Final[int] = 32
API_KEY_HASH_SUFFIX_LENGTH: Final[int] = API_KEY_HASH_LENGTH - len(API_KEY_HASH_PREFIX)

API_KEY_ENCRYPTION_PREFIX: Final[str] = "ak:v1:"
API_KEY_ENCRYPTION_SEPARATOR: Final[str] = ":"

logger = logging.getLogger(__name__)


def is_api_key_hash(value: str) -> bool:
    return value.startswith(API_KEY_HASH_PREFIX) and len(value) == API_KEY_HASH_LENGTH


@functools.lru_cache(maxsize=1)
def _get_hash_key() -> bytes:
    key_base64 = settings.MESSAGE_CONTENT_ENCRYPTION_KEY
    try:
        key = base64.b64decode(key_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid base64 message content encryption key") from exc

    if len(key) != crypto.KEY_SIZE:
        raise ValueError(
            f"Invalid message content encryption key length {len(key)}. Expected {crypto.KEY_SIZE}."
        )
    return key


def hash_api_key(api_key: str) -> str:
    digest = hmac.new(_get_hash_key(), api_key.encode(), hashlib.sha256).digest()
    encoded = base64.b32encode(digest).decode("ascii").rstrip("=")
    return f"{API_KEY_HASH_PREFIX}{encoded[:API_KEY_HASH_SUFFIX_LENGTH]}"


def get_api_key_hash_for_storage(value: str) -> str:
    if is_api_key_hash(value):
        return value
    return hash_api_key(value)


def _get_api_key_storage_dir() -> str:
    return settings.API_KEY_STORAGE_DIR


def _get_api_key_storage_path(api_key_hash: str) -> str:
    directory = _get_api_key_storage_dir()
    return os.path.join(directory, api_key_hash[:2], api_key_hash[2:])


def _get_associated_data(api_key_hash: str) -> bytes:
    return f"api_key:{api_key_hash}".encode()


def _encrypt_api_key(api_key: str, api_key_hash: str) -> str:
    key = _get_hash_key()
    nonce = crypto.generate_nonce()
    ciphertext = crypto.encrypt_chacha20_poly1305(
        key,
        api_key.encode(),
        nonce,
        associated_data=_get_associated_data(api_key_hash),
    )
    nonce_b64 = base64.b64encode(nonce).decode()
    ciphertext_b64 = base64.b64encode(ciphertext).decode()
    return f"{API_KEY_ENCRYPTION_PREFIX}{nonce_b64}{API_KEY_ENCRYPTION_SEPARATOR}{ciphertext_b64}"


def _decrypt_api_key(encoded: str, api_key_hash: str) -> str:
    if not encoded.startswith(API_KEY_ENCRYPTION_PREFIX):
        raise ValueError("Invalid API key encryption prefix")
    encoded = encoded.removeprefix(API_KEY_ENCRYPTION_PREFIX)
    nonce_b64, ciphertext_b64 = encoded.split(API_KEY_ENCRYPTION_SEPARATOR, 1)
    nonce = base64.b64decode(nonce_b64, validate=True)
    ciphertext = base64.b64decode(ciphertext_b64, validate=True)
    key = _get_hash_key()
    plaintext = crypto.decrypt_chacha20_poly1305(
        key,
        nonce,
        ciphertext,
        associated_data=_get_associated_data(api_key_hash),
    )
    return plaintext.decode()


def write_api_key_to_storage(api_key: str, api_key_hash: str) -> None:
    file_path = _get_api_key_storage_path(api_key_hash)
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    encoded = _encrypt_api_key(api_key, api_key_hash)
    temp_path = f"{file_path}.tmp"
    with open(temp_path, "w", encoding="utf-8") as handle:
        handle.write(encoded)
    os.replace(temp_path, file_path)


def read_api_key_from_storage(api_key_hash: str) -> str:
    file_path = _get_api_key_storage_path(api_key_hash)
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            encoded = handle.read().strip()
    except FileNotFoundError as exc:
        logger.warning("API key file missing for hash %s", api_key_hash)
        raise exc
    return _decrypt_api_key(encoded, api_key_hash)


def delete_api_key_from_storage(api_key_hash: str) -> None:
    file_path = _get_api_key_storage_path(api_key_hash)
    try:
        os.remove(file_path)
    except FileNotFoundError:
        return


def get_user_api_key(user_profile: object) -> str:
    api_key_value = user_profile.api_key
    if is_api_key_hash(api_key_value):
        return read_api_key_from_storage(api_key_value)
    migrate_api_key_from_legacy(user_profile, api_key_value)
    return api_key_value


def resolve_api_key_value(api_key_value: str, user_id: int | None = None) -> str:
    if is_api_key_hash(api_key_value):
        return read_api_key_from_storage(api_key_value)
    if user_id is not None:
        legacy_user = types.SimpleNamespace(id=user_id, api_key=api_key_value)
        migrate_api_key_from_legacy(legacy_user, api_key_value)
    return api_key_value


def ensure_api_key_storage(user_profile: object, api_key: str | None = None) -> str:
    api_key_value = api_key or user_profile.api_key
    api_key_hash = get_api_key_hash_for_storage(api_key_value)
    if is_api_key_hash(api_key_value):
        return api_key_hash

    write_api_key_to_storage(api_key_value, api_key_hash)
    models.UserProfile.objects.filter(id=user_profile.id).update(api_key=api_key_hash)
    if hasattr(user_profile, "api_key"):
        user_profile.api_key = api_key_hash
    return api_key_hash


def migrate_api_key_from_legacy(user_profile: object, api_key: str) -> None:
    try:
        ensure_api_key_storage(user_profile, api_key=api_key)
    except Exception:
        logger.exception("Failed to migrate API key to storage")
