
from dataclasses import dataclass
from pathlib import Path

import yaml


class IdentityRegistryError(Exception):
    """Raised when identity registry configuration is invalid."""


class IdentityNotFound(IdentityRegistryError):
    """Raised when an identity does not exist or is disabled."""


class PermissionDenied(IdentityRegistryError):
    """Raised when an identity lacks a required permission."""


@dataclass(frozen=True)
class Organization:
    organization_id: str
    name: str
    enabled: bool


@dataclass(frozen=True)
class Role:
    role_id: str
    permissions: frozenset[str]


@dataclass(frozen=True)
class Identity:
    identity_id: str
    name: str
    organization: str
    role: str
    personal_vault: str
    agent_id: str
    enabled: bool


class IdentityRegistry:
    def __init__(
        self,
        organizations: dict,
        roles: dict,
        identities: dict,
    ):
        self.organizations = organizations
        self.roles = roles
        self.identities = identities

    @classmethod
    def load(cls, registry_path: str | Path):
        path = Path(registry_path)

        if not path.is_file():
            raise IdentityRegistryError(
                f"Identity registry file not found: {path}"
            )

        try:
            with path.open("r", encoding="utf-8") as file:
                data = yaml.safe_load(file)
        except (OSError, yaml.YAMLError) as exc:
            raise IdentityRegistryError(
                f"Could not load identity registry: {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise IdentityRegistryError(
                "Identity registry must contain a YAML mapping."
            )

        for section in ("organizations", "roles", "identities"):
            if not isinstance(data.get(section), dict):
                raise IdentityRegistryError(
                    f"Registry section '{section}' must be a mapping."
                )

        organizations = {}
        for organization_id, item in data["organizations"].items():
            if not isinstance(item, dict):
                raise IdentityRegistryError(
                    f"Invalid organization: {organization_id}"
                )

            name = item.get("name")
            enabled = item.get("enabled")

            if not isinstance(name, str) or not name.strip():
                raise IdentityRegistryError(
                    f"Organization '{organization_id}' needs a name."
                )

            if not isinstance(enabled, bool):
                raise IdentityRegistryError(
                    f"Organization '{organization_id}' needs a boolean enabled value."
                )

            organizations[organization_id] = Organization(
                organization_id=organization_id,
                name=name.strip(),
                enabled=enabled,
            )

        roles = {}
        for role_id, item in data["roles"].items():
            if not isinstance(item, dict):
                raise IdentityRegistryError(f"Invalid role: {role_id}")

            permissions = item.get("permissions")

            if not isinstance(permissions, list):
                raise IdentityRegistryError(
                    f"Role '{role_id}' permissions must be a list."
                )

            if any(
                not isinstance(permission, str) or not permission.strip()
                for permission in permissions
            ):
                raise IdentityRegistryError(
                    f"Role '{role_id}' contains an invalid permission."
                )

            roles[role_id] = Role(
                role_id=role_id,
                permissions=frozenset(permissions),
            )

        identities = {}
        required_fields = (
            "name",
            "organization",
            "role",
            "personal_vault",
            "agent_id",
            "enabled",
        )

        for identity_id, item in data["identities"].items():
            if not isinstance(item, dict):
                raise IdentityRegistryError(
                    f"Invalid identity: {identity_id}"
                )

            for field in required_fields:
                value = item.get(field)

                if field == "enabled":
                    if not isinstance(value, bool):
                        raise IdentityRegistryError(
                            f"Identity '{identity_id}' needs a boolean enabled value."
                        )
                elif not isinstance(value, str) or not value.strip():
                    raise IdentityRegistryError(
                        f"Identity '{identity_id}' has an invalid '{field}'."
                    )

            organization_id = item["organization"]
            role_id = item["role"]

            if organization_id not in organizations:
                raise IdentityRegistryError(
                    f"Identity '{identity_id}' references unknown organization '{organization_id}'."
                )

            if role_id not in roles:
                raise IdentityRegistryError(
                    f"Identity '{identity_id}' references unknown role '{role_id}'."
                )

            identities[identity_id] = Identity(
                identity_id=identity_id,
                name=item["name"].strip(),
                organization=organization_id,
                role=role_id,
                personal_vault=item["personal_vault"].strip(),
                agent_id=item["agent_id"].strip(),
                enabled=item["enabled"],
            )

        return cls(
            organizations=organizations,
            roles=roles,
            identities=identities,
        )

    def get_identity(self, identity_id: str) -> Identity:
        identity = self.identities.get(identity_id)

        if identity is None or not identity.enabled:
            raise IdentityNotFound(
                f"Identity is missing or disabled: {identity_id}"
            )

        organization = self.organizations[identity.organization]

        if not organization.enabled:
            raise IdentityNotFound(
                f"Organization is disabled: {identity.organization}"
            )

        return identity

    def get_role(self, identity_id: str) -> Role:
        identity = self.get_identity(identity_id)
        return self.roles[identity.role]

    def has_permission(
        self,
        identity_id: str,
        permission: str,
    ) -> bool:
        role = self.get_role(identity_id)
        return permission in role.permissions

    def require_permission(
        self,
        identity_id: str,
        permission: str,
    ) -> None:
        if not self.has_permission(identity_id, permission):
            raise PermissionDenied(
                f"Identity '{identity_id}' lacks permission '{permission}'."
            )
