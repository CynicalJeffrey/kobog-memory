
import pytest
from pathlib import Path

from kobog_memory.config import load_config
from kobog_memory.core.vault_manager import VaultManager
from kobog_memory.governance.approval import (
    ApprovalError,
    MemoryApprovalManager,
)
from kobog_memory.governance.proposals import MemoryProposalManager


@pytest.fixture
def approval_environment(tmp_path):
    vault_path = tmp_path / "Test-Vault"
    (vault_path / "Memory" / "Inbox").mkdir(parents=True)
    (vault_path / "Memory" / "Approved").mkdir(parents=True)
    (vault_path / "Memory" / "Rejected").mkdir(parents=True)

    config_path = tmp_path / "vaults.yaml"
    config_path.write_text(
        f"""
system:
  name: KOBOG
  memory_policy: approval_required

vaults:
  test_vault:
    name: Test Vault
    path: {vault_path}
    organization: Test-Org
    enabled: true

permissions:
  default_access: deny
  cross_organization_sharing: approval_required
  memory_writes: proposal_only
  permanent_updates: administrator_approval
"""
    )

    config = load_config(config_path)
    vault_manager = VaultManager(
        config,
        allowed_vault_ids={"test_vault"},
    )

    audit_directory = tmp_path / "audit"

    proposal_manager = MemoryProposalManager(
        vault_manager,
        audit_directory,
    )

    approval_manager = MemoryApprovalManager(
        vault_manager,
        audit_directory,
        administrator_ids={"admin-1"},
    )

    proposal = proposal_manager.create_proposal(
        vault_id="test_vault",
        title="Test Memory",
        content="This is verified institutional knowledge.",
        reason="Testing the approval workflow.",
    )

    return {
        "vault_path": vault_path,
        "approval_manager": approval_manager,
        "proposal": proposal,
        "audit_directory": audit_directory,
    }


def test_unauthorized_user_cannot_approve(approval_environment):
    manager = approval_environment["approval_manager"]
    proposal = approval_environment["proposal"]

    with pytest.raises(ApprovalError):
        manager.decide(
            vault_id="test_vault",
            proposal_id=proposal["id"],
            actor_id="unauthorized-user",
            decision="approve",
        )


def test_admin_can_approve_proposal(approval_environment):
    manager = approval_environment["approval_manager"]
    proposal = approval_environment["proposal"]

    result = manager.decide(
        vault_id="test_vault",
        proposal_id=proposal["id"],
        actor_id="admin-1",
        decision="approve",
    )

    assert result is not None


def test_admin_can_reject_proposal(approval_environment):
    manager = approval_environment["approval_manager"]
    proposal = approval_environment["proposal"]

    result = manager.decide(
        vault_id="test_vault",
        proposal_id=proposal["id"],
        actor_id="admin-1",
        decision="reject",
    )

    assert result is not None


def test_approved_proposal_moves_to_approved_folder(approval_environment):
    manager = approval_environment["approval_manager"]
    proposal = approval_environment["proposal"]
    vault_path = approval_environment["vault_path"]

    manager.decide(
        vault_id="test_vault",
        proposal_id=proposal["id"],
        actor_id="admin-1",
        decision="approve",
    )

    approved_files = list(
        (vault_path / "Memory" / "Approved").glob("*.md")
    )

    assert len(approved_files) == 1
    assert not list(
        (vault_path / "Memory" / "Inbox").glob("*.md")
    )


def test_rejected_proposal_moves_to_rejected_folder(approval_environment):
    manager = approval_environment["approval_manager"]
    proposal = approval_environment["proposal"]
    vault_path = approval_environment["vault_path"]

    manager.decide(
        vault_id="test_vault",
        proposal_id=proposal["id"],
        actor_id="admin-1",
        decision="reject",
    )

    rejected_files = list(
        (vault_path / "Memory" / "Rejected").glob("*.md")
    )

    assert len(rejected_files) == 1
    assert not list(
        (vault_path / "Memory" / "Inbox").glob("*.md")
    )


def test_approval_creates_audit_record(approval_environment):
    manager = approval_environment["approval_manager"]
    proposal = approval_environment["proposal"]
    audit_directory = approval_environment["audit_directory"]

    manager.decide(
        vault_id="test_vault",
        proposal_id=proposal["id"],
        actor_id="admin-1",
        decision="approve",
    )

    audit_file = audit_directory / "decisions.jsonl"

    assert audit_file.exists()
    assert audit_file.read_text().strip()


def test_nonexistent_proposal_cannot_be_approved(approval_environment):
    manager = approval_environment["approval_manager"]

    with pytest.raises(ApprovalError):
        manager.decide(
            vault_id="test_vault",
            proposal_id="does-not-exist",
            actor_id="admin-1",
            decision="approve",
        )
