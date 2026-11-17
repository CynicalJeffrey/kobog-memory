
import json
import os
import re
import uuid

from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import yaml

from kobog_memory.core.vault_manager import (
    VaultManager,
    InvalidVaultPath,
    VaultAccessDenied,
    VaultNotFound,
)


class ProposalError(Exception):
    """Raised when a memory proposal cannot be created."""


class MemoryProposalManager:
    """Submit proposed memory updates without approving them."""

    MAX_TITLE_LENGTH = 200
    MAX_CONTENT_LENGTH = 50_000
    MAX_REASON_LENGTH = 2_000
    MAX_SOURCE_LENGTH = 200

    ALLOWED_TYPES = {
        "identity",
        "operational",
        "procedural",
        "decision",
        "project",
        "client",
        "research",
        "episodic",
        "strategic",
    }

    ALLOWED_ACCESS = {
        "public",
        "internal",
        "confidential",
        "restricted",
    }

    ALLOWED_STATUSES = {
        "proposed",
        "approved",
        "rejected",
        "archived",
        "superseded",
    }

    ORGANIZATION_PREFIXES = {
        "kobog_core": "KBG",
        "kameleon_tech": "KT",
        "andoticta": "ANICTA",
    }

    ID_PATTERN = re.compile(
        r"^KBG-[A-Z0-9]+-"
        r"[0-9a-fA-F]{8}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{12}$"
    )

    REQUIRED_METADATA = {
        "id",
        "title",
        "type",
        "organization",
        "vault_id",
        "status",
        "created",
        "updated",
        "source",
        "access",
        "derived_from",
    }

    @staticmethod
    def _validate_iso_datetime(value: str, field: str) -> None:
        if not isinstance(value, str):
            raise ProposalError(
                f"Metadata field '{field}' must be an ISO 8601 date."
            )

        try:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ProposalError(
                f"Metadata field '{field}' must be a valid ISO 8601 date."
            )

    @staticmethod
    def _validate_tags(tags: list) -> list:
        if not isinstance(tags, list):
            raise ProposalError("Metadata tags must be a list.")

        for tag in tags:
            if not isinstance(tag, str) or not re.fullmatch(
                r"[a-z0-9]+(?:-[a-z0-9]+)*", tag
            ):
                raise ProposalError(
                    "Tags must be lowercase and hyphenated."
                )

        return tags

    @staticmethod
    def _validate_source_url(source_url: str) -> str:
        if not isinstance(source_url, str):
            raise ProposalError("source_url must be a valid URL.")

        parsed = urlparse(source_url)

        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ProposalError("source_url must use HTTP or HTTPS.")

        return source_url

    @staticmethod
    def _validate_relationships(derived_from):
        if derived_from is None:
            return []

        if isinstance(derived_from, str):
            derived_from = [derived_from]

        if not isinstance(derived_from, list):
            raise ProposalError(
                "derived_from must be a string or a list of strings."
            )

        validated = []

        for reference in derived_from:
            if not isinstance(reference, str):
                raise ProposalError(
                    "Relationship references must be strings."
                )

            reference = reference.strip()

            if not reference or len(reference) > 500:
                raise ProposalError(
                    "Invalid relationship reference."
                )

            if "\x00" in reference:
                raise ProposalError(
                    "A relationship reference contains an invalid character."
                )

            validated.append(reference)

        return validated

    def _validate_metadata(self, metadata: dict) -> dict:
        """Validate required metadata before writing a proposal."""

        missing = self.REQUIRED_METADATA - metadata.keys()

        if missing:
            raise ProposalError(
                f"Missing required metadata fields: {', '.join(sorted(missing))}"
            )

        for field in self.REQUIRED_METADATA:
            value = metadata[field]

            if value is None or value == "":
                raise ProposalError(
                    f"Metadata field '{field}' cannot be empty."
                )

        for field in ("created", "updated"):
            self._validate_iso_datetime(metadata[field], field)

        if metadata["status"] not in self.ALLOWED_STATUSES:
            raise ProposalError("Invalid metadata lifecycle status.")

        if metadata["status"] != "proposed":
            raise ProposalError(
                "New proposals must have status 'proposed'."
            )

        if metadata["type"] not in self.ALLOWED_TYPES:
            raise ProposalError("Invalid metadata type.")

        if "tags" in metadata:
            self._validate_tags(metadata["tags"])

        if metadata["access"] not in self.ALLOWED_ACCESS:
            raise ProposalError("Invalid metadata access level.")

        if not self.ID_PATTERN.fullmatch(metadata["id"]):
            raise ProposalError("Invalid proposal ID format.")

        return metadata

    def __init__(
        self,
        vault_manager: VaultManager,
        audit_directory: Path | str,
    ):
        self.vault_manager = vault_manager
        self.audit_directory = (
            Path(audit_directory).expanduser().resolve()
        )

    @staticmethod
    def _validate_text(
        value: str,
        field: str,
        maximum: int,
    ) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ProposalError(
                f"{field} must be a non-empty string."
            )

        value = value.strip()

        if len(value) > maximum:
            raise ProposalError(
                f"{field} exceeds the maximum length of {maximum} characters."
            )

        if "\x00" in value:
            raise ProposalError(
                f"{field} contains an invalid character."
            )

        return value

    @staticmethod
    def _slugify(title: str) -> str:
        slug = re.sub(
            r"[^a-zA-Z0-9]+",
            "-",
            title.lower(),
        ).strip("-")

        return slug[:60] or "memory-proposal"

    @staticmethod
    def _get_identifier_prefix(vault_id: str) -> str:
        """Return a stable identifier prefix for a configured vault."""

        prefix = MemoryProposalManager.ORGANIZATION_PREFIXES.get(
            vault_id
        )

        if prefix:
            return prefix

        # New organizational and personal vaults receive a prefix
        # derived from their configured vault ID.
        prefix = re.sub(
            r"[^A-Z0-9]",
            "",
            vault_id.upper(),
        )[:12]

        if not prefix:
            raise ProposalError(
                f"Cannot generate an identifier prefix for vault: {vault_id}"
            )

        return prefix

    def _validate_source_references(
        self,
        vault_id: str,
        derived_from: list[str],
    ) -> list[str]:
        """Verify that referenced source records exist in the same vault."""

        validated = []

        for reference in derived_from:
            try:
                source_path = self.vault_manager.resolve_path(
                    vault_id,
                    reference,
                    must_exist=True,
                )
            except (
                InvalidVaultPath,
                VaultAccessDenied,
                VaultNotFound,
            ) as exc:
                raise ProposalError(
                    f"Referenced source is inaccessible: {reference}"
                ) from exc

            if source_path.suffix.lower() != ".md":
                raise ProposalError(
                    f"Referenced source must be a Markdown file: {reference}"
                )

            if not source_path.is_file():
                raise ProposalError(
                    f"Referenced source is not a file: {reference}"
                )

            vault = self.vault_manager.get_vault(vault_id)

            validated.append(
                source_path.relative_to(vault.path).as_posix()
            )

        return validated

    def _write_audit_record(self, record: dict) -> None:
        self.audit_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        audit_file = self.audit_directory / "proposals.jsonl"

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
            os.write(descriptor, payload)
        finally:
            os.close(descriptor)

    def create_proposal(
        self,
        vault_id: str,
        title: str,
        content: str,
        reason: str,
        source: str = "hermes",
        memory_type: str = "operational",
        access: str = "internal",
        derived_from=None,
        department: str = None,
        project: str = None,
        tags: list = None,
        author: str = None,
        review_date: str = None,
        related: list = None,
        source_url: str = None,
    ) -> dict:
        """Create a new Markdown proposal in an authorized vault's Inbox."""

        title = self._validate_text(
            title, "Title", self.MAX_TITLE_LENGTH
        )

        content = self._validate_text(
            content, "Content", self.MAX_CONTENT_LENGTH
        )

        reason = self._validate_text(
            reason, "Reason", self.MAX_REASON_LENGTH
        )

        source = self._validate_text(
            source, "Source", self.MAX_SOURCE_LENGTH
        )

        if department is not None:
            department = self._validate_text(
                department, "Department", 200
            )

        if project is not None:
            project = self._validate_text(
                project, "Project", 200
            )

        if author is not None:
            author = self._validate_text(
                author, "Author", 200
            )

        if tags is not None:
            self._validate_tags(tags)

        if review_date is not None:
            self._validate_iso_datetime(
                review_date,
                "review_date",
            )

        if source_url is not None:
            source_url = self._validate_source_url(source_url)

        if memory_type not in self.ALLOWED_TYPES:
            raise ProposalError("Invalid memory type.")

        if access not in self.ALLOWED_ACCESS:
            raise ProposalError("Invalid access level.")

        derived_from = self._validate_relationships(
            derived_from
        )

        related = self._validate_relationships(related)

        derived_from = self._validate_source_references(
            vault_id,
            derived_from,
        )

        try:
            vault = self.vault_manager.get_vault(vault_id)

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
            raise ProposalError(
                f"Cannot access the proposal destination for '{vault_id}'."
            ) from exc

        if not inbox.is_dir():
            raise ProposalError(
                "The proposal destination is not a directory."
            )

        organization_prefix = self._get_identifier_prefix(vault_id)

        proposal_id = (
            f"KBG-{organization_prefix}-{uuid.uuid4()}"
        )

        if not self.ID_PATTERN.fullmatch(proposal_id):
            raise ProposalError(
                "Generated proposal ID has an invalid format."
            )

        created = datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        )

        metadata = {
            "id": proposal_id,
            "title": title,
            "type": memory_type,
            "organization": vault.organization,
            "vault_id": vault_id,
            "status": "proposed",
            "created": created,
            "updated": created,
            "source": source,
            "access": access,
            "derived_from": derived_from,
        }

        optional_metadata = {
            "department": department,
            "project": project,
            "tags": tags,
            "author": author,
            "review_date": review_date,
            "related": related,
            "source_url": source_url,
        }

        for key, value in optional_metadata.items():
            if value is not None:
                metadata[key] = value

        metadata = self._validate_metadata(metadata)

        frontmatter = yaml.safe_dump(
            metadata,
            sort_keys=False,
            allow_unicode=True,
        )

        document = (
            f"---\n{frontmatter}---\n\n"
            f"# {title}\n\n"
            f"{content}\n\n"
            f"## Reason for proposal\n\n"
            f"{reason}\n"
        )

        filename = (
            f"{datetime.now(timezone.utc).strftime('%Y%m%d')}-"
            f"{self._slugify(title)}-{proposal_id[:8]}.md"
        )

        proposal_path = inbox / filename

        try:
            descriptor = os.open(
                proposal_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )

            with os.fdopen(
                descriptor,
                "w",
                encoding="utf-8",
            ) as file:
                file.write(document)

        except FileExistsError as exc:
            raise ProposalError(
                "A proposal with this filename already exists. Please retry."
            ) from exc

        except OSError as exc:
            raise ProposalError(
                "Unable to write the proposal to the vault."
            ) from exc

        audit_record = {
            "event": "memory_proposal_created",
            "id": proposal_id,
            "vault_id": vault_id,
            "organization": vault.organization,
            "source": source,
            "created": created,
            "filename": filename,
            "status": "proposed",
        }

        self._write_audit_record(audit_record)

        return {
            **audit_record,
            "path": f"Memory/Inbox/{filename}",
        }
