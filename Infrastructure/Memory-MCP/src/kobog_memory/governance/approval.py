
import json
import os
import re
import uuid

from datetime import datetime, timezone
from pathlib import Path

import yaml

from kobog_memory.core.vault_manager import (
    VaultManager,
    InvalidVaultPath,
    VaultAccessDenied,
    VaultNotFound,
)


class ApprovalError(Exception):
    """Raised when a memory proposal decision cannot be completed."""


class MemoryApprovalManager:
    """Allows authorized administrators to approve or reject proposals."""

    PROPOSAL_ID_PATTERN = re.compile(
        r"^KBG-[A-Z0-9]+-"
        r"(?P<uuid>"
        r"[0-9a-fA-F]{8}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{12}"
        r")$"
    )

    def __init__(
        self,
        vault_manager: VaultManager,
        audit_directory: Path | str,
        administrator_ids: set[str | int],
    ):
        self.vault_manager = vault_manager
        self.audit_directory = Path(audit_directory).expanduser().resolve()
        self.administrator_ids = {
            str(admin_id) for admin_id in administrator_ids
        }

        if not self.administrator_ids:
            raise ApprovalError(
                "At least one administrator ID must be configured."
            )

    def _authorize(self, actor_id: str | int) -> str:
        actor = str(actor_id)

        if actor not in self.administrator_ids:
            raise ApprovalError(
                "You are not authorized to decide proposals."
            )

        return actor

    @staticmethod
    def _read_frontmatter(path: Path) -> tuple[dict, str]:
        try:
            document = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ApprovalError(
                "Unable to read the proposal."
            ) from exc

        if not document.startswith("---\n"):
            raise ApprovalError(
                "Proposal has invalid YAML frontmatter."
            )

        parts = document.split("---", 2)

        if len(parts) != 3:
            raise ApprovalError(
                "Proposal has incomplete frontmatter."
            )

        try:
            metadata = yaml.safe_load(parts[1])
        except yaml.YAMLError as exc:
            raise ApprovalError(
                "Proposal frontmatter is invalid."
            ) from exc

        if not isinstance(metadata, dict):
            raise ApprovalError(
                "Proposal metadata must be a YAML mapping."
            )

        return metadata, parts[2]

    def _find_proposal(
        self,
        vault_id: str,
        proposal_id: str,
    ) -> Path:
        try:
            inbox = self.vault_manager.resolve_path(
                vault_id,
                "Memory/Inbox",
                must_exist=True,
            )
        except (
            InvalidVaultPath,
            VaultAccessDenied,
            VaultNotFound,
        ) as exc:
            raise ApprovalError(
                "Cannot access this proposal inbox."
            ) from exc

        matches = []

        for candidate in inbox.glob("*.md"):
            try:
                resolved = self.vault_manager.resolve_path(
                    vault_id,
                    f"Memory/Inbox/{candidate.name}",
                    must_exist=True,
                )
            except (
                InvalidVaultPath,
                VaultAccessDenied,
                VaultNotFound,
            ):
                continue

            if not resolved.is_file():
                continue

            metadata, _ = self._read_frontmatter(resolved)

            if metadata.get("id") == proposal_id:
                matches.append(resolved)

        if not matches:
            raise ApprovalError(
                "Proposal was not found in the inbox."
            )

        if len(matches) > 1:
            raise ApprovalError(
                "Multiple proposals share this ID."
            )

        return matches[0]

    def _write_audit_record(self, record: dict) -> None:
        self.audit_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        audit_file = self.audit_directory / "decisions.jsonl"

        payload = (
            json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
            ) + "\n"
        ).encode("utf-8")

        descriptor = os.open(
            audit_file,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o600,
        )

        try:
            remaining = memoryview(payload)

            while remaining:
                written = os.write(descriptor, remaining)

                if written <= 0:
                    raise ApprovalError(
                        "Unable to complete the audit record."
                    )

                remaining = remaining[written:]

        finally:
            os.close(descriptor)

    def decide(
        self,
        vault_id: str,
        proposal_id: str,
        actor_id: str | int,
        decision: str,
    ) -> dict:
        """Approve or reject a pending proposal."""

        actor = self._authorize(actor_id)

        if decision not in {"approve", "reject"}:
            raise ApprovalError(
                "Decision must be 'approve' or 'reject'."
            )

        if not isinstance(proposal_id, str):
            raise ApprovalError("Invalid proposal ID.")

        match = self.PROPOSAL_ID_PATTERN.fullmatch(proposal_id)

        if not match:
            raise ApprovalError("Invalid proposal ID.")

        try:
            uuid.UUID(match.group("uuid"))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ApprovalError("Invalid proposal ID.") from exc

        try:
            vault = self.vault_manager.get_vault(vault_id)

            source = self._find_proposal(
                vault_id,
                proposal_id,
            )

            metadata, body = self._read_frontmatter(source)

            if metadata.get("id") != proposal_id:
                raise ApprovalError(
                    "Proposal ID does not match."
                )

            if metadata.get("vault_id") != vault_id:
                raise ApprovalError(
                    "Proposal vault identity does not match."
                )

            if metadata.get("organization") != vault.organization:
                raise ApprovalError(
                    "Proposal organization identity does not match."
                )

            if metadata.get("status") != "proposed":
                raise ApprovalError(
                    "This proposal has already been decided."
                )

            destination_folder = (
                "Memory/Approved"
                if decision == "approve"
                else "Memory/Rejected"
            )

            destination_directory = self.vault_manager.resolve_path(
                vault_id,
                destination_folder,
                must_exist=True,
            )

            if not destination_directory.is_dir():
                raise ApprovalError(
                    "Decision destination is not a directory."
                )

            destination = destination_directory / source.name

            if destination.exists():
                raise ApprovalError(
                    "A file with this name already exists."
                )

            decided_at = datetime.now(timezone.utc).isoformat(
                timespec="seconds"
            )

            status = (
                "approved"
                if decision == "approve"
                else "rejected"
            )

            metadata["status"] = status
            metadata["updated"] = decided_at
            metadata["decided_at"] = decided_at
            metadata["decided_by"] = actor

            if decision == "approve":
                metadata["approved_at"] = decided_at
                metadata["approved_by"] = actor

            frontmatter = yaml.safe_dump(
                metadata,
                sort_keys=False,
                allow_unicode=True,
            )

            updated_document = (
                f"---\n{frontmatter}---{body}"
            )

            os.replace(source, destination)

            temporary = destination.with_name(
                f".{destination.name}.{uuid.uuid4().hex}.tmp"
            )

            try:
                descriptor = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )

                with os.fdopen(
                    descriptor,
                    "w",
                    encoding="utf-8",
                ) as file:
                    file.write(updated_document)

                os.replace(temporary, destination)

            finally:
                if temporary.exists():
                    temporary.unlink()

            event = (
                "memory_proposal_approved"
                if decision == "approve"
                else "memory_proposal_rejected"
            )

            record = {
                "event": event,
                "id": proposal_id,
                "vault_id": vault_id,
                "organization": vault.organization,
                "decision": decision,
                "decided_by": actor,
                "decided_at": decided_at,
                "filename": destination.name,
            }

            self._write_audit_record(record)

            return {
                **record,
                "path": (
                    f"{destination_folder}/{destination.name}"
                ),
                "status": status,
            }

        except (
            InvalidVaultPath,
            VaultAccessDenied,
            VaultNotFound,
        ) as exc:
            raise ApprovalError(
                "Access to the requested vault was denied."
            ) from exc

        except OSError as exc:
            raise ApprovalError(
                "Unable to complete the proposal decision."
            ) from exc
