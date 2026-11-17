
from kobog_memory.core.identity_registry import (
    IdentityRegistry,
    IdentityNotFound,
    PermissionDenied,
)


class AccessControlError(Exception):
    """Raised when a vault access request is invalid."""


class AccessController:
    def __init__(self, identity_registry: IdentityRegistry):
        self.identity_registry = identity_registry

    def authorize_vault_access(
        self,
        identity_id: str,
        vault,
        permission: str,
    ) -> None:
        """
        Authorize an identity to perform an operation in a vault.

        The vault must be a VaultConfig returned by the trusted
        VaultManager, not a vault description supplied by an agent.
        """

        identity = self.identity_registry.get_identity(identity_id)

        if not isinstance(permission, str) or not permission.strip():
            raise AccessControlError("A valid permission is required.")

        permission = permission.strip()

        # Find whether this vault is assigned as someone's personal vault.
        personal_vault_owners = [
            registered_identity
            for registered_identity in self.identity_registry.identities.values()
            if registered_identity.personal_vault == vault.vault_id
        ]

        if personal_vault_owners:
            # Personal vaults are private to their assigned identity.
            if len(personal_vault_owners) != 1:
                raise AccessControlError(
                    "Personal vault ownership is ambiguous."
                )

            owner = personal_vault_owners[0]

            if owner.identity_id != identity.identity_id:
                raise PermissionDenied(
                    "This personal vault belongs to another identity."
                )

            if not permission.startswith("personal."):
                raise PermissionDenied(
                    "Personal vaults cannot be accessed using organizational permissions."
                )

            self.identity_registry.require_permission(
                identity_id,
                permission,
            )
            return

            organization = self.identity_registry.organizations[
                identity.organization
            ]

            if vault.organization != organization.name:
                raise PermissionDenied(
                    "This identity cannot access another organization's vault."
                    )

        if not permission.startswith("organization."):
            raise PermissionDenied(
                "Organizational vaults require an organizational permission."
            )

        self.identity_registry.require_permission(
            identity_id,
            permission,
        )
