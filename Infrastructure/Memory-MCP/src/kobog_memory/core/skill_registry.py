
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from kobog_memory.core.vault_manager import (
    VaultManager,
    InvalidVaultPath,
    VaultAccessDenied,
    VaultNotFound,
)


class SkillRegistryError(Exception):
    """Raised when skill discovery or retrieval fails."""


@dataclass(frozen=True)
class Skill:
    skill_id: str
    name: str
    description: str
    version: str
    owner: str
    scope: str
    status: str
    vault_id: str
    relative_path: str
    required_permissions: tuple[str, ...]


class SkillRegistry:
    """Discovers and retrieves skills within authorized repositories."""

    SKILL_ID_PATTERN = re.compile(r"^[A-Z0-9][A-Z0-9._-]{2,127}$")

    REQUIRED_FIELDS = (
        "id",
        "name",
        "description",
        "version",
        "owner",
        "scope",
        "status",
    )

    def __init__(
        self,
        vault_manager: VaultManager,
        identity_registry,
        identity_id: str,
        global_vault_manager: VaultManager | None = None,
        global_vault_id: str = "kobog_core",
    ):
        self.vault_manager = vault_manager
        self.identity_registry = identity_registry
        self.identity = identity_registry.get_identity(identity_id)

        self.organization = identity_registry.organizations[
            self.identity.organization
        ]

        self.global_vault_manager = global_vault_manager
        self.global_vault_id = global_vault_id

        if global_vault_manager is not None:
            global_vault_manager.get_vault(global_vault_id)

    @staticmethod
    def _normalize(value: str) -> str:
        return re.sub(r"[^a-z0-9]", "", value.casefold())

    def _has_scope_permission(self, scope: str) -> bool:
        if scope == "global":
            # Global skills are available to authenticated agents.
            return True

        if scope == "organization":
            return self.identity_registry.has_permission(
                self.identity.identity_id,
                "organization.skills.read",
            )

        if scope == "personal":
            return self.identity_registry.has_permission(
                self.identity.identity_id,
                "personal.skills.read",
            )

        return False

    def _get_repositories(self) -> list[tuple]:
        """Return skill repositories accessible to this identity."""

        repositories = []

        if self.global_vault_manager is not None:
            repositories.append(
                (
                    self.global_vault_manager,
                    self.global_vault_id,
                    "global",
                    "KOBOG-Corp",
                    "Skills/Global",
                )
            )

        for vault in self.vault_manager.list_accessible_vaults():

            if vault.vault_id == self.identity.personal_vault:
                repositories.append(
                    (
                        self.vault_manager,
                        vault.vault_id,
                        "personal",
                        self.identity.identity_id,
                        "Skills/Personal",
                    )
                )

            elif (
                self._normalize(vault.organization)
                == self._normalize(self.organization.name)
            ):
                repositories.append(
                    (
                        self.vault_manager,
                        vault.vault_id,
                        "organization",
                        self.organization.name,
                        "Skills/Shared",
                    )
                )

        return [
            repository
            for repository in repositories
            if self._has_scope_permission(repository[2])
        ]

    @staticmethod
    def _read_frontmatter(path: Path) -> dict:
        try:
            document = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise SkillRegistryError(
                "Unable to read skill definition."
            ) from exc

        if not document.startswith("---\n"):
            raise SkillRegistryError(
                "Skill definition has no YAML frontmatter."
            )

        parts = document.split("---", 2)

        if len(parts) != 3:
            raise SkillRegistryError(
                "Skill definition has incomplete frontmatter."
            )

        try:
            metadata = yaml.safe_load(parts[1])
        except yaml.YAMLError as exc:
            raise SkillRegistryError(
                "Skill definition contains invalid YAML."
            ) from exc

        if not isinstance(metadata, dict):
            raise SkillRegistryError(
                "Skill metadata must be a YAML mapping."
            )

        return metadata

    def _validate_metadata(
        self,
        metadata: dict,
        expected_scope: str,
        expected_owner: str,
    ) -> None:

        for field in self.REQUIRED_FIELDS:
            value = metadata.get(field)

            if not isinstance(value, str) or not value.strip():
                raise SkillRegistryError(
                    f"Skill metadata requires a valid '{field}'."
                )

        skill_id = metadata["id"].strip()

        if not self.SKILL_ID_PATTERN.fullmatch(skill_id):
            raise SkillRegistryError(
                "Skill ID has an invalid format."
            )

        if metadata["scope"] != expected_scope:
            raise SkillRegistryError(
                "Skill ownership scope does not match its repository."
            )

        if metadata["status"] != "active":
            raise SkillRegistryError(
                "Skill is not active."
            )

        if expected_scope == "global":
            owner_matches = (
                self._normalize(metadata["owner"])
                == self._normalize("KOBOG-Corp")
            )

        elif expected_scope == "organization":
            owner_matches = (
                self._normalize(metadata["owner"])
                in {
                    self._normalize(self.identity.organization),
                    self._normalize(self.organization.name),
                }
            )

        else:
            owner_matches = (
                metadata["owner"] == self.identity.identity_id
            )

        if not owner_matches:
            raise SkillRegistryError(
                "Skill owner does not match its authorized repository."
            )

        required_permissions = metadata.get(
            "required_permissions",
            [],
        )

        if not isinstance(required_permissions, list):
            raise SkillRegistryError(
                "required_permissions must be a list."
            )

        if any(
            not isinstance(permission, str)
            or not permission.strip()
            for permission in required_permissions
        ):
            raise SkillRegistryError(
                "Skill contains an invalid required permission."
            )

        for permission in required_permissions:
            if not self.identity_registry.has_permission(
                self.identity.identity_id,
                permission,
            ):
                raise SkillRegistryError(
                    "Identity lacks a permission required by this skill."
                )

    def discover_skills(self) -> list[Skill]:
        """Discover active skills available to the current identity."""

        discovered = []
        discovered_ids = set()

        for (
            manager,
            vault_id,
            scope,
            owner,
            skill_directory,
        ) in self._get_repositories():

            try:
                root = manager.resolve_path(
                    vault_id,
                    skill_directory,
                    must_exist=True,
                )
            except (
                InvalidVaultPath,
                VaultAccessDenied,
                VaultNotFound,
            ):
                continue

            if not root.is_dir():
                continue

            for candidate in sorted(root.iterdir()):

                if not candidate.is_dir():
                    continue

                relative_path = (
                    f"{skill_directory}/"
                    f"{candidate.name}/SKILL.md"
                )

                try:
                    skill_path = manager.resolve_path(
                        vault_id,
                        relative_path,
                        must_exist=True,
                    )

                    if not skill_path.is_file():
                        continue

                    metadata = self._read_frontmatter(skill_path)

                    self._validate_metadata(
                        metadata,
                        expected_scope=scope,
                        expected_owner=owner,
                    )

                except (
                    SkillRegistryError,
                    InvalidVaultPath,
                    VaultAccessDenied,
                    VaultNotFound,
                ):
                    # Invalid or unauthorized skills are not exposed.
                    continue

                skill_id = metadata["id"].strip()

                if skill_id in discovered_ids:
                    raise SkillRegistryError(
                        f"Duplicate skill ID detected: {skill_id}"
                    )

                discovered_ids.add(skill_id)

                discovered.append(
                    Skill(
                        skill_id=skill_id,
                        name=metadata["name"].strip(),
                        description=metadata["description"].strip(),
                        version=metadata["version"].strip(),
                        owner=metadata["owner"].strip(),
                        scope=scope,
                        status=metadata["status"].strip(),
                        vault_id=vault_id,
                        relative_path=relative_path,
                        required_permissions=tuple(
                            metadata.get("required_permissions", [])
                        ),
                    )
                )

        return discovered

    def read_skill(self, skill_id: str) -> str:
        """Retrieve instructions for an authorized active skill."""

        if not isinstance(skill_id, str) or not skill_id.strip():
            raise SkillRegistryError("A valid skill ID is required.")

        matches = [
            skill
            for skill in self.discover_skills()
            if skill.skill_id == skill_id
        ]

        if not matches:
            raise SkillRegistryError(
                "Skill is unavailable or unauthorized."
            )

        if len(matches) != 1:
            raise SkillRegistryError(
                "Skill ID is ambiguous."
            )

        skill = matches[0]

        manager = (
            self.global_vault_manager
            if skill.scope == "global"
            else self.vault_manager
        )

        try:
            path = manager.resolve_path(
                skill.vault_id,
                skill.relative_path,
                must_exist=True,
            )

            return path.read_text(encoding="utf-8")

        except (
            InvalidVaultPath,
            VaultAccessDenied,
            VaultNotFound,
            OSError,
        ) as exc:
            raise SkillRegistryError(
                "Unable to retrieve skill instructions."
            ) from exc
