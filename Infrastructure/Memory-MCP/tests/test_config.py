
from pathlib import Path

import pytest

from kobog_memory.config import load_config, ConfigurationError


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = PROJECT_ROOT / "config" / "vaults.yaml"


def test_loads_all_five_vaults():
    config = load_config(CONFIG_PATH)

    assert config.system_name == "KOBOG"
    assert config.memory_policy == "approval_required"

    assert set(config.vaults) == {
        "kobog_core",
        "kameleon_tech",
        "andoticta",
        "kt_ceo",
        "kt_employee_01",
    }


def test_all_enabled_vaults_exist():
    config = load_config(CONFIG_PATH)

    for vault in config.vaults.values():
        assert vault.enabled
        assert vault.path.is_dir()


def test_vaults_have_correct_organizations():
    config = load_config(CONFIG_PATH)

    assert config.vaults["kobog_core"].organization == "shared"
    assert config.vaults["kameleon_tech"].organization == "Kameleon-Tech"
    assert config.vaults["andoticta"].organization == "ANdotICTA"
    assert config.vaults["kt_ceo"].organization == "Kameleon-Tech"
    assert config.vaults["kt_employee_01"].organization == "Kameleon-Tech"


def test_memory_governance_settings():
    config = load_config(CONFIG_PATH)

    assert config.permissions["default_access"] == "deny"
    assert config.permissions["memory_writes"] == "proposal_only"
    assert config.permissions["permanent_updates"] == "administrator_approval"


def test_rejects_missing_config():
    with pytest.raises(ConfigurationError):
        load_config(PROJECT_ROOT / "config" / "missing.yaml")
