
from dataclasses import asdict, dataclass
from typing import Any

from kobog_memory.core.identity_registry import (
    IdentityRegistry,
)


class AgentContextError(Exception):
    """Raised when an agent context cannot be safely assembled."""


@dataclass(frozen=True)
class AgentContext:
    """Trusted runtime context describing an authenticated agent."""

    context_version: str

    system: str

    identity_id: str
    identity_name: str
    agent_id: str

    organization_id: str
    organization_name: str

    role_id: str
    permissions: tuple[str, ...]

    personal_vault_id: str
    organization_vault_ids: tuple[str, ...]
    accessible_vault_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return the context as a structured dictionary."""

        return {
            "context_version": self.context_version,
            "system": self.system,
            "identity": {
                "identity_id": self.identity_id,
                "name": self.identity_name,
                "agent_id": self.agent_id,
            },
            "organization": {
                "organization_id": self.organization_id,
                "name": self.organization_name,
            },
            "role": {
                "role_id": self.role_id,
                "permissions": list(self.permissions),
            },
            "knowledge_access": {
                "personal_vault_id": self.personal_vault_id,
                "organization_vault_ids": list(
                    self.organization_vault_ids
                ),
                "accessible_vault_ids": list(
                    self.accessible_vault_ids
                ),
            },
        }


class AgentContextBuilder:
    """
    Assemble trusted context for one authenticated agent.

    This component describes existing authorization.
    It does not grant permissions or perform memory access.
    """

    CONTEXT_VERSION = "1.0"
    SYSTEM_NAME = "KOBOG"

    def __init__(
        self,
        identity_registry: IdentityRegistry,
        identity_id: str,
        accessible_vault_ids: set[str],
        organization_vault_ids: set[str],
    ):
        self.identity_registry = identity_registry
        self.identity_id = identity_id

        self.accessible_vault_ids = frozenset(
            accessible_vault_ids
        )

        self.organization_vault_ids = frozenset(
            organization_vault_ids
        )

    def build(self) -> AgentContext:
        """Build the trusted context for the configured identity."""

        if not self.identity_id:
            raise AgentContextError(
                "An identity ID is required."
            )

        try:
            identity = self.identity_registry.get_identity(
                self.identity_id
            )
        except Exception as exc:
            raise AgentContextError(
                f"Could not resolve agent identity: {exc}"
            ) from exc

        organization = self.identity_registry.organizations.get(
            identity.organization
        )

        if organization is None or not organization.enabled:
            raise AgentContextError(
                "The agent's organization is unavailable."
            )

        try:
            role = self.identity_registry.get_role(
                identity.identity_id
            )
        except Exception as exc:
            raise AgentContextError(
                f"Could not resolve agent role: {exc}"
            ) from exc

        permitted_vault_ids = (
            set(self.organization_vault_ids)
            | {identity.personal_vault}
        )

        unauthorized_vault_ids = (
            self.accessible_vault_ids - permitted_vault_ids
        )

        if unauthorized_vault_ids:
            raise AgentContextError(
                "The context contains vaults outside the "
                "agent's permitted scope: "
                + ", ".join(sorted(unauthorized_vault_ids))
            )

        if identity.personal_vault not in self.accessible_vault_ids:
            raise AgentContextError(
                "The agent's personal vault is missing from "
                "its accessible vaults."
            )

        accessible_organization_vaults = (
            self.accessible_vault_ids
            & self.organization_vault_ids
        )

        return AgentContext(
            context_version=self.CONTEXT_VERSION,
            system=self.SYSTEM_NAME,
            identity_id=identity.identity_id,
            identity_name=identity.name,
            agent_id=identity.agent_id,
            organization_id=identity.organization,
            organization_name=organization.name,
            role_id=identity.role,
            permissions=tuple(sorted(role.permissions)),
            personal_vault_id=identity.personal_vault,
            organization_vault_ids=tuple(
                sorted(accessible_organization_vaults)
            ),
            accessible_vault_ids=tuple(
                sorted(self.accessible_vault_ids)
            ),
        )
