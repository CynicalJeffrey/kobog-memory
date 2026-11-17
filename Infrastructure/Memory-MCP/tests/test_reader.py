from pathlib import Path

import pytest

from kobog_memory.config import (
    MemoryConfig,
    VaultConfig,
)
from kobog_memory.core.vault_manager import VaultManager
from kobog_memory.core.reader import (
    MemoryReader,
    NoteReadError,
)


@pytest.fixture
def reader(tmp_path):
    vault_path = tmp_path / "Kameleon-Tech"

    approved = vault_path / "Memory" / "Approved"
    inbox = vault_path / "Memory" / "Inbox"

    approved.mkdir(parents=True)
    inbox.mkdir(parents=True)

    (approved / "business.md").write_text(
        "# Kameleon Tech\n\n"
        "Our business provides technology solutions.\n"
        "We offer phone appraisal services.\n",
        encoding="utf-8",
    )

    (inbox / "proposal.md").write_text(
        "Unapproved information must remain private.",
        encoding="utf-8",
    )

    config = MemoryConfig(
        system_name="KOBOG",
        memory_policy="approval_required",
        vaults={
            "kameleon_tech": VaultConfig(
                vault_id="kameleon_tech",
                name="Kameleon Tech",
                path=vault_path.resolve(),
                organization="Kameleon-Tech",
                enabled=True,
            )
        },
        permissions={
            "default_access": "deny",
            "cross_organization_sharing": "approval_required",
            "memory_writes": "proposal_only",
            "permanent_updates": "administrator_approval",
        },
    )

    manager = VaultManager(
        config=config,
        allowed_vault_ids={"kameleon_tech"},
    )

    return MemoryReader(manager)


def test_reads_approved_note(reader):
    content = reader.read_note(
        "kameleon_tech",
        "business.md",
    )

    assert "technology solutions" in content


def test_cannot_read_inbox_note(reader):
    with pytest.raises(NoteReadError):
        reader.read_note(
            "kameleon_tech",
            "../Inbox/proposal.md",
        )


def test_cannot_read_outside_approved_memory(reader):
    with pytest.raises(NoteReadError):
        reader.read_note(
            "kameleon_tech",
            "../../Identity/identity.md",
        )


def test_rejects_non_markdown_files(reader):
    with pytest.raises(NoteReadError):
        reader.read_note(
            "kameleon_tech",
            "business.txt",
        )


def test_searches_approved_notes(reader):
    results = reader.search_approved(
        "kameleon_tech",
        "phone appraisal",
    )

    assert len(results) == 1
    assert results[0].vault_id == "kameleon_tech"
    assert results[0].path == "Memory/Approved/business.md"
    assert results[0].line_number == 4


def test_search_does_not_return_inbox_content(reader):
    results = reader.search_approved(
        "kameleon_tech",
        "Unapproved information",
    )

    assert results == []


def test_rejects_empty_search(reader):
    with pytest.raises(ValueError):
        reader.search_approved("kameleon_tech", "  ")


def test_rejects_invalid_search_limit(reader):
    with pytest.raises(ValueError):
        reader.search_approved(
            "kameleon_tech",
            "technology",
            limit=500,
        )
