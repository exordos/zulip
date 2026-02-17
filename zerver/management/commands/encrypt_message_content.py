#    Copyright 2026 Genesis Corporation.
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

import typing

import typing_extensions

import zerver.lib.management
import zerver.lib.message_encryption
import zerver.models.messages


class Command(zerver.lib.management.ZulipBaseCommand):
    @typing_extensions.override
    def add_arguments(self, parser: typing.Any) -> None:
        parser.add_argument(
            "--batch-size",
            type=int,
            default=1000,
            help="Number of messages to update per batch.",
        )
        parser.add_argument(
            "--skip-archived",
            action="store_true",
            help="Skip encrypting archived messages.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report how many messages would be updated without saving changes.",
        )

    @typing_extensions.override
    def handle(self, *args: typing.Any, **options: typing.Any) -> None:
        batch_size = options["batch_size"]
        dry_run = options["dry_run"]
        skip_archived = options["skip_archived"]

        total_updated = self._encrypt_queryset(
            zerver.models.messages.Message,
            batch_size,
            dry_run,
        )
        if not skip_archived:
            total_updated += self._encrypt_queryset(
                zerver.models.messages.ArchivedMessage,
                batch_size,
                dry_run,
            )

        action = "Would update" if dry_run else "Updated"
        self.stdout.write(f"{action} {total_updated} messages.")

    def _encrypt_queryset(
        self,
        model: type[zerver.models.messages.AbstractMessage],
        batch_size: int,
        dry_run: bool,
    ) -> int:
        updated_count = 0
        batch: list[zerver.models.messages.AbstractMessage] = []

        queryset = model.objects.all().only(
            "id", "content", "rendered_content", "edit_history"
        )
        for message in queryset.iterator(chunk_size=batch_size):
            updated_fields: list[str] = []

            encrypted_content = self._encrypt_if_needed(message.content)
            if encrypted_content != message.content:
                message.content = encrypted_content
                updated_fields.append("content")

            encrypted_rendered = self._encrypt_if_needed(message.rendered_content)
            if encrypted_rendered != message.rendered_content:
                message.rendered_content = encrypted_rendered
                updated_fields.append("rendered_content")

            if message.edit_history is not None:
                encrypted_history = zerver.lib.message_encryption.encrypt_edit_history(
                    message.edit_history
                )
                if encrypted_history != message.edit_history:
                    message.edit_history = encrypted_history
                    updated_fields.append("edit_history")

            if updated_fields:
                batch.append(message)

            if len(batch) >= batch_size:
                updated_count += self._flush_batch(batch, dry_run)

        if batch:
            updated_count += self._flush_batch(batch, dry_run)

        return updated_count

    def _flush_batch(
        self,
        batch: list[zerver.models.messages.AbstractMessage],
        dry_run: bool,
    ) -> int:
        if not dry_run:
            model = type(batch[0])
            model.objects.bulk_update(
                batch,
                ["content", "rendered_content", "edit_history"],
            )
        batch_size = len(batch)
        batch.clear()
        return batch_size

    def _encrypt_if_needed(self, value: str | None) -> str | None:
        if value is None:
            return None
        if value.startswith(zerver.lib.message_encryption.ENCRYPTED_MESSAGE_PREFIX):
            return value
        return zerver.lib.message_encryption.encrypt_message_text(value)
