from __future__ import annotations

import typing

import typing_extensions

import zerver.lib.management
import zerver.lib.message_encryption
import zerver.models.messages
from zerver.models import recipients


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
        parser.add_argument(
            "--user-ids",
            default="",
            help=(
                "Comma-separated list of user IDs. When provided, only direct messages where "
                "the sender or any recipient is in this list will be encrypted."
            ),
        )

    @typing_extensions.override
    def handle(self, *args: typing.Any, **options: typing.Any) -> None:
        batch_size = options["batch_size"]
        dry_run = options["dry_run"]
        skip_archived = options["skip_archived"]
        user_ids = self._parse_user_ids(options["user_ids"])

        total_updated = self._encrypt_queryset(
            zerver.models.messages.Message,
            batch_size,
            dry_run,
            user_ids,
        )
        if not skip_archived:
            total_updated += self._encrypt_queryset(
                zerver.models.messages.ArchivedMessage,
                batch_size,
                dry_run,
                user_ids,
            )

        action = "Would update" if dry_run else "Updated"
        self.stdout.write(f"{action} {total_updated} messages.")

    def _encrypt_queryset(
        self,
        model: type[zerver.models.messages.AbstractMessage],
        batch_size: int,
        dry_run: bool,
        user_ids: set[int],
    ) -> int:
        updated_count = 0
        batch: list[zerver.models.messages.AbstractMessage] = []

        queryset = model.raw_objects.values(
            "id",
            "content",
            "rendered_content",
            "edit_history",
            "date_sent",
            "recipient_id",
            "recipient__type",
            "recipient__type_id",
            "realm_id",
            "sender_id",
            "sender__realm_id",
        )
        recipient_cache: dict[int, zerver.models.recipients.Recipient] = {}
        for row in queryset.iterator(chunk_size=batch_size):
            if user_ids and not self._matches_user_ids(row, user_ids, recipient_cache):
                continue
            updated_fields: list[str] = []

            associated_data = zerver.lib.message_encryption._get_row_associated_data(row)
            encrypted_content = self._encrypt_if_needed(row["content"], associated_data)
            if encrypted_content != row["content"]:
                updated_fields.append("content")

            encrypted_rendered = self._encrypt_if_needed(
                row["rendered_content"],
                associated_data,
            )
            if encrypted_rendered != row["rendered_content"]:
                updated_fields.append("rendered_content")

            encrypted_history = row["edit_history"]
            if encrypted_history is not None:
                encrypted_history = zerver.lib.message_encryption.encrypt_edit_history(
                    encrypted_history,
                    associated_data,
                )
                if encrypted_history != row["edit_history"]:
                    updated_fields.append("edit_history")

            if updated_fields:
                batch.append(
                    model(
                        id=row["id"],
                        content=typing.cast(str, encrypted_content),
                        rendered_content=encrypted_rendered,
                        edit_history=encrypted_history,
                    )
                )

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
            model.raw_objects.bulk_update(
                batch,
                ["content", "rendered_content", "edit_history"],
            )
        batch_size = len(batch)
        batch.clear()
        return batch_size

    def _encrypt_if_needed(self, value: str | None, associated_data: bytes) -> str | None:
        if value is None:
            return None
        if value.startswith(zerver.lib.message_encryption.ENCRYPTED_MESSAGE_PREFIX):
            return value
        return zerver.lib.message_encryption.encrypt_message_text(value, associated_data)

    def _parse_user_ids(self, raw_user_ids: str) -> set[int]:
        if not raw_user_ids:
            return set()

        user_ids: set[int] = set()
        for item in raw_user_ids.split(","):
            cleaned = item.strip()
            if not cleaned:
                continue
            user_ids.add(int(cleaned))
        return user_ids

    def _matches_user_ids(
        self,
        row: typing.Mapping[str, typing.Any],
        user_ids: set[int],
        recipient_cache: dict[int, zerver.models.recipients.Recipient],
    ) -> bool:
        recipient_type = row["recipient__type"]
        if recipient_type != recipients.Recipient.DIRECT_MESSAGE_GROUP:
            return False

        recipient_id = typing.cast(int, row["recipient_id"])
        recipient = recipient_cache.get(recipient_id)
        if recipient is None:
            recipient = recipients.Recipient.objects.get(id=recipient_id)
            recipient_cache[recipient_id] = recipient
        participant_ids = set(recipients.get_direct_message_group_user_ids(recipient))
        participant_ids.add(row["sender_id"])
        return bool(participant_ids.intersection(user_ids))
