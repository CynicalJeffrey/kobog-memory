from pathlib import Path

from kobog_memory.config import MemoryConfig, VaultConfig


class VaultAccessDenied(Exception):
    """Raised when an access profile cannot access a vault."""


class VaultNotFound(Exception):
    """Raised when a vault does not exist or is disabled."""


class InvalidVaultPath(Exception):
    """Raised when a requested path is unsafe."""


class VaultManager:
    """Controls access to configured KOBOG vault directories."""

    BLOCKED_DIRECTORIES = {".git", ".obsidian"}

    def __init__(
        self,
        config: MemoryConfig,
        allowed_vault_ids: set[str],
    ):
        self.config = config
        self.allowed_vault_ids = frozenset(allowed_vault_ids)

        unknown_ids = self.allowed_vault_ids - set(config.vaults)

        if unknown_ids:
            raise VaultNotFound(
                f"Unknown vault IDs: {', '.join(sorted(unknown_ids))}"
            )

    def list_accessible_vaults(self) -> list[VaultConfig]:
        """Return enabled vaults permitted by this access profile."""

        return [
            vault
            for vault_id, vault in self.config.vaults.items()
            if vault_id in self.allowed_vault_ids and vault.enabled
        ]

    def get_vault(self, vault_id: str) -> VaultConfig:
        """Return a vault only if this access profile is authorized."""

        if vault_id not in self.allowed_vault_ids:
            raise VaultAccessDenied(
                f"Access denied to vault: {vault_id}"
            )

        vault = self.config.vaults.get(vault_id)

        if vault is None or not vault.enabled:
            raise VaultNotFound(
                f"Vault is unavailable: {vault_id}"
            )

        return vault

    def resolve_path(
        self,
        vault_id: str,
        relative_path: str,
        must_exist: bool = False,
    ) -> Path:
        """Safely resolve a relative path within an authorized vault."""

        vault = self.get_vault(vault_id)

        if not isinstance(relative_path, str) or not relative_path.strip():
            raise InvalidVaultPath("A relative file path is required.")

        requested = Path(relative_path)

        if requested.is_absolute():
            raise InvalidVaultPath("Absolute paths are not permitted.")

        if ".." in requested.parts:
            raise InvalidVaultPath("Path traversal is not permitted.")

        if any(
            part in self.BLOCKED_DIRECTORIES
            for part in requested.parts
        ):
            raise InvalidVaultPath(
                "Access to internal application directories is blocked."
            )

        root = vault.path.resolve()
        resolved = (root / requested).resolve()

        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise InvalidVaultPath(
                "The requested path escapes the vault directory."
            ) from exc

        if must_exist and not resolved.exists():
            raise InvalidVaultPath(
                f"Path does not exist: {relative_path}"
            )

        return resolved

    def list_markdown_files(
        self,
        vault_id: str,
        relative_directory: str = "",
    ) -> list[str]:
        """List Markdown files inside an authorized vault directory."""

        vault = self.get_vault(vault_id)

        if relative_directory:
            directory = self.resolve_path(
                vault_id,
                relative_directory,
                must_exist=True,
            )

            if not directory.is_dir():
                raise InvalidVaultPath(
                    "The requested path is not a directory."
                )
        else:
            directory = vault.path.resolve()

        results = []

        for candidate in directory.rglob("*.md"):
            if any(
                part in self.BLOCKED_DIRECTORIES
                for part in candidate.relative_to(vault.path).parts
            ):
                continue

            try:
                resolved = self.resolve_path(
                    vault_id,
                    str(candidate.relative_to(vault.path)),
                    must_exist=True,
                )
            except (InvalidVaultPath, VaultNotFound):
                continue

            if resolved.is_file():
                results.append(
                    resolved.relative_to(vault.path).as_posix()
                )

        return sorted(results)
