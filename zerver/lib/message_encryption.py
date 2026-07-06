from __future__ import annotations

import base64
import binascii
import datetime
import functools
import logging
import typing

import django.conf
import orjson

from zerver.lib import crypto
from zerver.models import recipients, users

logger = logging.getLogger(__name__)

ENCRYPTED_MESSAGE_PREFIX = "enc:v1:"
ENCRYPTED_MESSAGE_SEPARATOR = ":"
ENCRYPTED_MESSAGE_PLACEHOLDER = "<encrypted text here>"


def _build_message_associated_data(
    *,
    date_sent: datetime.datetime,
    realm_id: int,
    recipient_id: int,
    sender_id: int,
) -> bytes:
    date_key = date_sent.strftime("%Y-%m-%dT%H:%M:%S.%f%z")
    return f"{realm_id}:{recipient_id}:{sender_id}:{date_key}".encode()


def _get_message_associated_data(message: typing.Any) -> bytes:
    return _build_message_associated_data(
        date_sent=message.date_sent,
        realm_id=message.realm_id,
        recipient_id=message.recipient_id,
        sender_id=message.sender_id,
    )


def _get_row_associated_data(row: typing.Mapping[str, typing.Any]) -> bytes:
    realm_id = typing.cast(int, row.get("realm_id", row.get("sender__realm_id")))
    return _build_message_associated_data(
        date_sent=row["date_sent"],
        realm_id=realm_id,
        recipient_id=row["recipient_id"],
        sender_id=row["sender_id"],
    )


def should_encrypt_message(message: typing.Any) -> bool:
    if not django.conf.settings.MESSAGE_CONTENT_ENCRYPTION_ENABLED:
        return False

    if django.conf.settings.ENCRYPT_ALL_MESSAGES:
        return True

    setting_user_ids = django.conf.settings.ENCRYPT_ALL_DIRECT_MESSAGE_FOR_USER_IDS
    if not setting_user_ids:
        return False

    participant_ids = _get_direct_message_participant_ids(message)
    if not participant_ids:
        return False

    realm_user_ids = _get_realm_user_ids(message, setting_user_ids)
    return bool(participant_ids.intersection(realm_user_ids))


def _get_realm_user_ids(message: typing.Any, user_ids: list[int]) -> set[int]:
    if not user_ids:
        return set()

    return set(
        users.UserProfile.objects.filter(
            id__in=user_ids,
            realm_id=message.realm_id,
        ).values_list("id", flat=True)
    )


def _get_direct_message_participant_ids(message: typing.Any) -> set[int]:
    recipient = message.recipient
    if recipient.type == recipients.Recipient.DIRECT_MESSAGE_GROUP:
        participant_ids = set(recipients.get_direct_message_group_user_ids(recipient))
        participant_ids.add(message.sender_id)
        return participant_ids

    return set()


@functools.lru_cache(maxsize=1)
def _get_message_content_key() -> bytes:
    key_base64 = django.conf.settings.MESSAGE_CONTENT_ENCRYPTION_KEY
    key: bytes
    try:
        key = base64.b64decode(key_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid base64 message content encryption key") from exc

    if len(key) != crypto.KEY_SIZE:
        raise ValueError(
            f"Invalid message content encryption key length {len(key)}. Expected {crypto.KEY_SIZE}."
        )
    return key


def encrypt_message_text(plaintext: str, associated_data: bytes) -> str:
    key = _get_message_content_key()
    nonce = crypto.generate_nonce()
    ciphertext = crypto.encrypt_chacha20_poly1305(
        key,
        plaintext.encode(),
        nonce,
        associated_data=associated_data,
    )
    nonce_b64 = base64.b64encode(nonce).decode()
    ciphertext_b64 = base64.b64encode(ciphertext).decode()
    return f"{ENCRYPTED_MESSAGE_PREFIX}{nonce_b64}{ENCRYPTED_MESSAGE_SEPARATOR}{ciphertext_b64}"


def encrypt_message_text_optional(value: str | None, associated_data: bytes) -> str | None:
    if value is None:
        return None
    return encrypt_message_text(value, associated_data)


def encrypt_edit_history(value: str, associated_data: bytes) -> str:
    try:
        history = orjson.loads(value)
    except orjson.JSONDecodeError:
        return value

    if not isinstance(history, list):
        return value

    updated = False
    for event in history:
        if not isinstance(event, dict):
            continue

        prev_content = event.get("prev_content")
        if isinstance(prev_content, str) and not prev_content.startswith(ENCRYPTED_MESSAGE_PREFIX):
            event["prev_content"] = encrypt_message_text(prev_content, associated_data)
            updated = True

        prev_rendered_content = event.get("prev_rendered_content")
        if isinstance(prev_rendered_content, str) and not prev_rendered_content.startswith(
            ENCRYPTED_MESSAGE_PREFIX
        ):
            event["prev_rendered_content"] = encrypt_message_text(
                prev_rendered_content,
                associated_data,
            )
            updated = True

    if not updated:
        return value
    return orjson.dumps(history).decode()


def decrypt_edit_history(value: str, associated_data: bytes) -> str:
    try:
        history = orjson.loads(value)
    except orjson.JSONDecodeError:
        return value

    if not isinstance(history, list):
        return value

    updated = False
    for event in history:
        if not isinstance(event, dict):
            continue

        prev_content = event.get("prev_content")
        if isinstance(prev_content, str):
            decrypted = decrypt_message_text(prev_content, associated_data)
            if decrypted != prev_content:
                event["prev_content"] = decrypted
                updated = True

        prev_rendered_content = event.get("prev_rendered_content")
        if isinstance(prev_rendered_content, str):
            decrypted = decrypt_message_text(prev_rendered_content, associated_data)
            if decrypted != prev_rendered_content:
                event["prev_rendered_content"] = decrypted
                updated = True

    if not updated:
        return value
    return orjson.dumps(history).decode()


def decrypt_message_text(value: str, associated_data: bytes) -> str:
    if not value.startswith(ENCRYPTED_MESSAGE_PREFIX):
        return value

    encoded = value.removeprefix(ENCRYPTED_MESSAGE_PREFIX)
    try:
        nonce_b64, ciphertext_b64 = encoded.split(ENCRYPTED_MESSAGE_SEPARATOR, 1)
        nonce = base64.b64decode(nonce_b64, validate=True)
        ciphertext = base64.b64decode(ciphertext_b64, validate=True)
        key = _get_message_content_key()
        plaintext = crypto.decrypt_chacha20_poly1305(
            key,
            nonce,
            ciphertext,
            associated_data=associated_data,
        )
        return plaintext.decode()
    except Exception:
        logger.exception("Failed to decrypt message text")
        return ENCRYPTED_MESSAGE_PLACEHOLDER


def decrypt_message_text_optional(value: str | None, associated_data: bytes) -> str | None:
    if value is None:
        return None
    return decrypt_message_text(value, associated_data)


def _row_has_encrypted_message_fields(row: typing.Mapping[str, typing.Any]) -> bool:
    for field_name in ("content", "rendered_content"):
        value = row.get(field_name)
        if isinstance(value, str) and value.startswith(ENCRYPTED_MESSAGE_PREFIX):
            return True

    edit_history = row.get("edit_history")
    return isinstance(edit_history, str) and ENCRYPTED_MESSAGE_PREFIX in edit_history


def encrypt_message_fields_for_database(
    message: typing.Any,
) -> tuple[str, str | None, str | None]:
    original_content = message.content
    original_rendered_content = message.rendered_content
    original_edit_history = message.edit_history
    if not should_encrypt_message(message):
        return original_content, original_rendered_content, original_edit_history
    associated_data = _get_message_associated_data(message)
    message.content = encrypt_message_text(original_content, associated_data)
    message.rendered_content = encrypt_message_text_optional(
        original_rendered_content, associated_data
    )
    if original_edit_history is not None:
        message.edit_history = encrypt_edit_history(original_edit_history, associated_data)
    return original_content, original_rendered_content, original_edit_history


def restore_message_fields_after_database_write(
    message: typing.Any, original_fields: tuple[str, str | None, str | None]
) -> None:
    message.content, message.rendered_content, message.edit_history = original_fields


def decrypt_message_fields(message: typing.Any) -> None:
    associated_data = _get_message_associated_data(message)
    message.content = decrypt_message_text(message.content, associated_data)
    message.rendered_content = decrypt_message_text_optional(
        message.rendered_content,
        associated_data,
    )
    if message.edit_history is not None:
        message.edit_history = decrypt_edit_history(message.edit_history, associated_data)


def decrypt_message_row(row: dict[str, typing.Any]) -> None:
    if not _row_has_encrypted_message_fields(row):
        return

    associated_data = _get_row_associated_data(row)
    if "content" in row:
        row["content"] = decrypt_message_text(row["content"], associated_data)
    if "rendered_content" in row:
        row["rendered_content"] = decrypt_message_text_optional(
            row["rendered_content"],
            associated_data,
        )
    if "edit_history" in row and row["edit_history"] is not None:
        row["edit_history"] = decrypt_edit_history(row["edit_history"], associated_data)
