from pathlib import Path

import pytest

from kobog_memory.config import load_config
from kobog_memory.core.vault_manager import (
    VaultManager,
    VaultAccessDenied,
    VaultNotFound,
    InvalidVaultPath,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = PROJECT_ROOT / "config" / "vaults.yaml"


@pytest.fixture
def manager():
    config = load_config(CONFIG_PATH)

    return VaultManager(
        config=config,
        allowed_vault_ids={"kameleon_tech"},
    )


def test_lists_only_authorized_vaults(manager):
    vaults = manager.list_accessible_vaults()

    assert len(vaults) == 1
    assert vaults[0].vault_id == "kameleon_tech"


def test_rejects_unauthorized_vault(manager):
    with pytest.raises(VaultAccessDenied):
        manager.get_vault("andoticta")


def test_resolves_path_inside_authorized_vault(manager):
    path = manager.resolve_path(
        "kameleon_tech",
        "Memory/Approved",
    )

    assert path.is_dir()
    assert path.is_relative_to(
        Path.home() / "KOBOG/Vaults/Kameleon-Tech"
    )


def test_rejects_path_traversal(manager):
    with pytest.raises(InvalidVaultPath):
        manager.resolve_path(
            "kameleon_tech",
            "../../ANdotICTA",
        )


def test_rejects_absolute_paths(manager):
    with pytest.raises(InvalidVaultPath):
        manager.resolve_path(
            "kameleon_tech",
            "/etc/passwd",
        )


def test_blocks_obsidian_internal_files(manager):
    with pytest.raises(InvalidVaultPath):
        manager.resolve_path(
            "kameleon_tech",
            ".obsidian/app.json",
        )


def test_rejects_unknown_vault():
    config = load_config(CONFIG_PATH)

    with pytest.raises(VaultNotFound):
        VaultManager(config, {"unknown_vault"})


def test_lists_markdown_files(manager):
    files = manager.list_markdown_files(
        "kameleon_tech",
        "Memory/Approved",
    )

    assert isinstance(files, list)
    assert all(file.endswith(".md") for file in files)
    assert all(not file.startswith("/") for file in files)
