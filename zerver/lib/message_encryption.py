#    Copyright 2026 Genesis Corporation.
#
#    All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from __future__ import annotations

import base64
import binascii
import typing

import django.conf
import orjson

from zerver.lib import crypto

ENCRYPTED_MESSAGE_PREFIX = "enc:v1:"
ENCRYPTED_MESSAGE_SEPARATOR = ":"


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


def encrypt_message_text(plaintext: str) -> str:
    key = _get_message_content_key()
    nonce = crypto.generate_nonce()
    ciphertext = crypto.encrypt_chacha20_poly1305(key, plaintext.encode(), nonce)
    nonce_b64 = base64.b64encode(nonce).decode()
    ciphertext_b64 = base64.b64encode(ciphertext).decode()
    return f"{ENCRYPTED_MESSAGE_PREFIX}{nonce_b64}{ENCRYPTED_MESSAGE_SEPARATOR}{ciphertext_b64}"


def encrypt_message_text_optional(value: str | None) -> str | None:
    if value is None:
        return None
    return encrypt_message_text(value)


def encrypt_edit_history(value: str) -> str:
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
            event["prev_content"] = encrypt_message_text(prev_content)
            updated = True

        prev_rendered_content = event.get("prev_rendered_content")
        if isinstance(prev_rendered_content, str) and not prev_rendered_content.startswith(
            ENCRYPTED_MESSAGE_PREFIX
        ):
            event["prev_rendered_content"] = encrypt_message_text(prev_rendered_content)
            updated = True

    if not updated:
        return value
    return orjson.dumps(history).decode()


def decrypt_edit_history(value: str) -> str:
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
            decrypted = decrypt_message_text(prev_content)
            if decrypted != prev_content:
                event["prev_content"] = decrypted
                updated = True

        prev_rendered_content = event.get("prev_rendered_content")
        if isinstance(prev_rendered_content, str):
            decrypted = decrypt_message_text(prev_rendered_content)
            if decrypted != prev_rendered_content:
                event["prev_rendered_content"] = decrypted
                updated = True

    if not updated:
        return value
    return orjson.dumps(history).decode()


def decrypt_message_text(value: str) -> str:
    if not value.startswith(ENCRYPTED_MESSAGE_PREFIX):
        return value

    encoded = value.removeprefix(ENCRYPTED_MESSAGE_PREFIX)
    try:
        nonce_b64, ciphertext_b64 = encoded.split(ENCRYPTED_MESSAGE_SEPARATOR, 1)
    except ValueError as exc:
        raise ValueError("Invalid encrypted message format") from exc

    try:
        nonce = base64.b64decode(nonce_b64, validate=True)
        ciphertext = base64.b64decode(ciphertext_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid encrypted message encoding") from exc

    key = _get_message_content_key()
    plaintext = crypto.decrypt_chacha20_poly1305(key, nonce, ciphertext)
    return plaintext.decode()


def decrypt_message_text_optional(value: str | None) -> str | None:
    if value is None:
        return None
    return decrypt_message_text(value)


def encrypt_message_fields_for_database(
    message: typing.Any,
) -> tuple[str, str | None, str | None]:
    original_content = message.content
    original_rendered_content = message.rendered_content
    original_edit_history = message.edit_history
    message.content = encrypt_message_text(original_content)
    message.rendered_content = encrypt_message_text_optional(original_rendered_content)
    if original_edit_history is not None:
        message.edit_history = encrypt_edit_history(original_edit_history)
    return original_content, original_rendered_content, original_edit_history


def restore_message_fields_after_database_write(
    message: typing.Any, original_fields: tuple[str, str | None, str | None]
) -> None:
    message.content, message.rendered_content, message.edit_history = original_fields


def decrypt_message_fields(message: typing.Any) -> None:
    message.content = decrypt_message_text(message.content)
    message.rendered_content = decrypt_message_text_optional(message.rendered_content)
    if message.edit_history is not None:
        message.edit_history = decrypt_edit_history(message.edit_history)


def decrypt_message_row(row: dict[str, typing.Any]) -> None:
    if "content" in row:
        row["content"] = decrypt_message_text(row["content"])
    if "rendered_content" in row:
        row["rendered_content"] = decrypt_message_text_optional(row["rendered_content"])
    if "edit_history" in row:
        if row["edit_history"] is not None:
            row["edit_history"] = decrypt_edit_history(row["edit_history"])
