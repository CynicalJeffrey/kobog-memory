from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


class ConfigurationError(Exception):
    """Raised when KOBOG configuration is invalid."""


@dataclass(frozen=True)
class VaultConfig:
    vault_id: str
    name: str
    path: Path
    organization: str
    enabled: bool


@dataclass(frozen=True)
class MemoryConfig:
    system_name: str
    memory_policy: str
    vaults: dict[str, VaultConfig]
    permissions: dict[str, Any]


def load_config(config_path: Path | str) -> MemoryConfig:
    """Load and validate the KOBOG vault configuration."""

    config_path = Path(config_path).expanduser().resolve()

    if not config_path.is_file():
        raise ConfigurationError(
            f"Configuration file not found: {config_path}"
        )

    try:
        with config_path.open("r", encoding="utf-8") as file:
            raw = yaml.safe_load(file)
    except yaml.YAMLError as exc:
        raise ConfigurationError(
            f"Invalid YAML configuration: {exc}"
        ) from exc

    if not isinstance(raw, dict):
        raise ConfigurationError(
            "Configuration must contain a YAML mapping."
        )

    system = raw.get("system")
    vault_definitions = raw.get("vaults")
    permissions = raw.get("permissions")

    if not isinstance(system, dict):
        raise ConfigurationError("Missing or invalid system section.")

    if not isinstance(vault_definitions, dict):
        raise ConfigurationError("Missing or invalid vaults section.")

    if not isinstance(permissions, dict):
        raise ConfigurationError("Missing or invalid permissions section.")

    system_name = system.get("name")
    memory_policy = system.get("memory_policy")

    if not isinstance(system_name, str) or not system_name.strip():
        raise ConfigurationError("System name must be a non-empty string.")

    if memory_policy != "approval_required":
        raise ConfigurationError(
            "Memory policy must be approval_required."
        )

    required_permissions = {
        "default_access": "deny",
        "cross_organization_sharing": "approval_required",
        "memory_writes": "proposal_only",
        "permanent_updates": "administrator_approval",
    }

    for key, expected_value in required_permissions.items():
        if permissions.get(key) != expected_value:
            raise ConfigurationError(
                f"Permission '{key}' must be '{expected_value}'."
            )

    vaults: dict[str, VaultConfig] = {}

    for vault_id, definition in vault_definitions.items():
        if not isinstance(vault_id, str) or not vault_id.strip():
            raise ConfigurationError("Invalid vault identifier.")

        if not isinstance(definition, dict):
            raise ConfigurationError(
                f"Invalid definition for vault '{vault_id}'."
            )

        name = definition.get("name")
        raw_path = definition.get("path")
        organization = definition.get("organization")
        enabled = definition.get("enabled")

        if not isinstance(name, str) or not name.strip():
            raise ConfigurationError(
                f"Vault '{vault_id}' has an invalid name."
            )

        if not isinstance(raw_path, str) or not raw_path.strip():
            raise ConfigurationError(
                f"Vault '{vault_id}' has an invalid path."
            )

        if not isinstance(organization, str) or not organization.strip():
            raise ConfigurationError(
                f"Vault '{vault_id}' has an invalid organization."
            )

        if not isinstance(enabled, bool):
            raise ConfigurationError(
                f"Vault '{vault_id}' must have a boolean enabled value."
            )

        vault_path = Path(raw_path).expanduser().resolve()

        if enabled and not vault_path.is_dir():
            raise ConfigurationError(
                f"Enabled vault directory does not exist: {vault_path}"
            )

        vaults[vault_id] = VaultConfig(
            vault_id=vault_id,
            name=name,
            path=vault_path,
            organization=organization,
            enabled=enabled,
        )

    if not any(vault.enabled for vault in vaults.values()):
        raise ConfigurationError("No enabled vaults were configured.")

    return MemoryConfig(
        system_name=system_name,
        memory_policy=memory_policy,
        vaults=vaults,
        permissions=permissions.copy(),
    )
