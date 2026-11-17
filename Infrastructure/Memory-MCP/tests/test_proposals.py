import json
from pathlib import Path

import pytest
import yaml

from kobog_memory.config import MemoryConfig, VaultConfig
from kobog_memory.core.vault_manager import VaultManager
from kobog_memory.governance.proposals import (
    MemoryProposalManager,
    ProposalError,
)


@pytest.fixture
def proposal_manager(tmp_path):
    vault_path = tmp_path / "Kameleon-Tech"
    (vault_path / "Memory" / "Inbox").mkdir(parents=True)
    (vault_path / "Memory" / "Approved").mkdir()
    (vault_path / "Memory" / "Rejected").mkdir()

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

    return MemoryProposalManager(
        vault_manager=manager,
        audit_directory=tmp_path / "audit",
    ), vault_path, tmp_path / "audit"


def test_creates_proposal_in_inbox(proposal_manager):
    manager, vault_path, _ = proposal_manager

    result = manager.create_proposal(
        vault_id="kameleon_tech",
        title="New Business Information",
        content="Kameleon Tech offers device appraisal.",
        reason="This is useful business information.",
    )

    proposal_file = vault_path / result["path"]

    assert proposal_file.is_file()
    assert result["status"] == "proposed"


def test_proposal_has_valid_frontmatter(proposal_manager):
    manager, vault_path, _ = proposal_manager

    result = manager.create_proposal(
        vault_id="kameleon_tech",
        title="Business Identity",
        content="Kameleon Tech provides technology services.",
        reason="Preserve the business identity.",
    )

    document = (vault_path / result["path"]).read_text(
        encoding="utf-8"
    )

    assert document.startswith("---\n")

    _, frontmatter, body = document.split("---", 2)
    metadata = yaml.safe_load(frontmatter)

    assert metadata["id"] == result["id"]
    assert metadata["organization"] == "Kameleon-Tech"
    assert metadata["status"] == "proposed"
    assert "# Business Identity" in body


def test_proposal_is_not_written_to_approved(proposal_manager):
    manager, vault_path, _ = proposal_manager

    manager.create_proposal(
        vault_id="kameleon_tech",
        title="Proposed Change",
        content="New information.",
        reason="It may be useful.",
    )

    approved = vault_path / "Memory" / "Approved"

    assert list(approved.iterdir()) == []


def test_creates_audit_record(proposal_manager):
    manager, _, audit_directory = proposal_manager

    result = manager.create_proposal(
        vault_id="kameleon_tech",
        title="Audit Test",
        content="Proposal content.",
        reason="Testing the audit log.",
    )

    audit_file = audit_directory / "proposals.jsonl"
    records = [
        json.loads(line)
        for line in audit_file.read_text(encoding="utf-8").splitlines()
    ]

    assert len(records) == 1
    assert records[0]["id"] == result["id"]
    assert records[0]["event"] == "memory_proposal_created"


def test_rejects_unauthorized_vault(proposal_manager):
    manager, _, _ = proposal_manager

    with pytest.raises(ProposalError):
        manager.create_proposal(
            vault_id="andoticta",
            title="Unauthorized",
            content="This should not be saved.",
            reason="Testing access restrictions.",
        )


def test_rejects_empty_content(proposal_manager):
    manager, _, _ = proposal_manager

    with pytest.raises(ProposalError):
        manager.create_proposal(
            vault_id="kameleon_tech",
            title="Empty Content",
            content="  ",
            reason="Testing validation.",
        )


def test_rejects_empty_title(proposal_manager):
    manager, _, _ = proposal_manager

    with pytest.raises(ProposalError):
        manager.create_proposal(
            vault_id="kameleon_tech",
            title=" ",
            content="Some content.",
            reason="Testing validation.",
        )


def test_rejects_oversized_content(proposal_manager):
    manager, _, _ = proposal_manager

    with pytest.raises(ProposalError):
        manager.create_proposal(
            vault_id="kameleon_tech",
            title="Large Proposal",
            content="x" * 50_001,
            reason="Testing the size limit.",
        )


def test_proposal_saves_optional_metadata(proposal_manager):
    manager, vault_path, _ = proposal_manager

    result = manager.create_proposal(
        vault_id="kameleon_tech",
        title="Business Process Update",
        content="Updated business process.",
        reason="Preserve the new process.",
        department="Operations",
        project="KOBOG",
        tags=["business-process", "operations"],
        author="Jeffrey",
        review_date="2027-01-01",
        related=["KBG-KT-123456"],
        source_url="https://example.com/source",
    )

    document = (vault_path / result["path"]).read_text(
        encoding="utf-8"
    )

    _, frontmatter, _ = document.split("---", 2)
    metadata = yaml.safe_load(frontmatter)

    assert metadata["department"] == "Operations"
    assert metadata["project"] == "KOBOG"
    assert metadata["tags"] == ["business-process", "operations"]
    assert metadata["author"] == "Jeffrey"
    assert metadata["review_date"] == "2027-01-01"
    assert metadata["related"] == ["KBG-KT-123456"]
    assert metadata["source_url"] == "https://example.com/source"


def test_rejects_invalid_source_url(proposal_manager):
    manager, _, _ = proposal_manager

    with pytest.raises(ProposalError):
        manager.create_proposal(
            vault_id="kameleon_tech",
            title="Invalid Source",
            content="Some content.",
            reason="Testing URL validation.",
            source_url="ftp://example.com/file",
        )
