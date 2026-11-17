
import os
import re
from dataclasses import asdict
from pathlib import Path

import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.middleware.cors import CORSMiddleware

from kobog_memory.config import load_config
from kobog_memory.core.vault_manager import VaultManager
from kobog_memory.core.reader import MemoryReader
from kobog_memory.core.skill_registry import SkillRegistry
from kobog_memory.core.agent_context import AgentContextBuilder
from kobog_memory.governance.proposals import MemoryProposalManager
from kobog_memory.governance.approval import MemoryApprovalManager
from kobog_memory.core.identity_registry import IdentityRegistry
from kobog_memory.core.access_control import AccessController


PROJECT_ROOT = Path(__file__).resolve().parents[2]

CONFIG_PATH = Path(
    os.environ.get(
        "KOBOG_CONFIG_PATH",
        PROJECT_ROOT / "config" / "vaults.yaml",
    )
)

AUDIT_DIRECTORY = Path(
    os.environ.get(
        "KOBOG_AUDIT_DIRECTORY",
        PROJECT_ROOT / "data" / "audit",
    )
)

IDENTITY_REGISTRY_PATH = Path(
    os.environ.get(
        "KOBOG_IDENTITY_REGISTRY",
        PROJECT_ROOT / "config" / "identity_registry.yaml",
    )
)


def normalize_organization(value: str) -> str:
    """Normalize organization names for consistent comparison."""
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def get_bool_env(name: str, default: bool = False) -> bool:
    """Read a boolean environment variable."""
    value = os.environ.get(name)

    if value is None:
        return default

    return value.strip().casefold() in {"1", "true", "yes", "on"}


def get_csv_env(name: str, default: str) -> list[str]:
    """Read a comma-separated environment variable."""
    value = os.environ.get(name, default)

    return [
        item.strip()
        for item in value.split(",")
        if item.strip()
    ]


def create_server() -> FastMCP:
    allowed_vaults = os.environ.get(
        "KOBOG_ALLOWED_VAULT_IDS",
        "",
    )

    allowed_vault_ids = {
        vault_id.strip()
        for vault_id in allowed_vaults.split(",")
        if vault_id.strip()
    }

    if not allowed_vault_ids:
        raise RuntimeError(
            "KOBOG_ALLOWED_VAULT_IDS must explicitly define "
            "the vaults this server instance may access."
        )

    config = load_config(CONFIG_PATH)

    identity_id = os.environ.get(
        "KOBOG_IDENTITY_ID",
        "",
    ).strip()

    if not identity_id:
        raise RuntimeError(
            "KOBOG_IDENTITY_ID must identify this server instance."
        )

    identity_registry = IdentityRegistry.load(
        IDENTITY_REGISTRY_PATH
    )

    identity = identity_registry.get_identity(identity_id)

    if not identity.enabled:
        raise RuntimeError("This identity is disabled.")

    organization = identity_registry.organizations[
        identity.organization
    ]

    if not organization.enabled:
        raise RuntimeError("This identity's organization is disabled.")

    access_controller = AccessController(identity_registry)

    personal_vault_ids = {
        registered_identity.personal_vault
        for registered_identity in identity_registry.identities.values()
        if registered_identity.personal_vault
    }

    organization_key = normalize_organization(organization.name)

    organization_vault_ids = {
        vault_id
        for vault_id, vault in config.vaults.items()
        if (
            normalize_organization(vault.organization) == organization_key
            and vault_id not in personal_vault_ids
        )
    }

    if not organization_vault_ids:
        raise RuntimeError(
            "No organizational vault is configured for "
            f"{organization.name}."
        )

    permitted_vault_ids = (
        organization_vault_ids | {identity.personal_vault}
    )

    unauthorized_vault_ids = (
        allowed_vault_ids - permitted_vault_ids
    )

    if unauthorized_vault_ids:
        raise RuntimeError(
            "The server allowlist contains vaults outside "
            "this identity's scope: "
            + ", ".join(sorted(unauthorized_vault_ids))
        )

    if identity.personal_vault not in allowed_vault_ids:
        raise RuntimeError(
            "The identity's personal vault must be included "
            "in KOBOG_ALLOWED_VAULT_IDS."
        )

    if not (allowed_vault_ids & organization_vault_ids):
        raise RuntimeError(
            "At least one organizational vault belonging to "
            "this identity must be included in the allowlist."
        )

    for vault_id in allowed_vault_ids:
        if vault_id not in config.vaults:
            raise RuntimeError(
                f"Unknown vault in access allowlist: {vault_id}"
            )

        if not config.vaults[vault_id].enabled:
            raise RuntimeError(
                f"Disabled vault cannot be accessed: {vault_id}"
            )

    # Ordinary memory access: personal and organizational vaults.
    vault_manager = VaultManager(
        config=config,
        allowed_vault_ids=allowed_vault_ids,
    )

    # Global skills use a separate manager.
    global_vault_id = "kobog_core"

    if global_vault_id not in config.vaults:
        raise RuntimeError(
            "The KOBOG Core vault is not configured."
        )

    if not config.vaults[global_vault_id].enabled:
        raise RuntimeError(
            "The KOBOG Core vault is disabled."
        )

    global_vault_manager = VaultManager(
        config=config,
        allowed_vault_ids={global_vault_id},
    )

    reader = MemoryReader(vault_manager)

    skill_registry = SkillRegistry(
        vault_manager=vault_manager,
        identity_registry=identity_registry,
        identity_id=identity.identity_id,
        global_vault_manager=global_vault_manager,
        global_vault_id=global_vault_id,
    )

    context_builder = AgentContextBuilder(
        identity_registry=identity_registry,
        identity_id=identity.identity_id,
        accessible_vault_ids=allowed_vault_ids,
        organization_vault_ids=organization_vault_ids,
    )

    proposals = MemoryProposalManager(
        vault_manager=vault_manager,
        audit_directory=AUDIT_DIRECTORY,
    )

    approval_manager = MemoryApprovalManager(
        vault_manager=vault_manager,
        audit_directory=AUDIT_DIRECTORY,
        administrator_ids={identity.identity_id},
    )

    def authorize_vault(
        vault_id: str,
        permission: str,
    ):
        vault = vault_manager.get_vault(vault_id)

        access_controller.authorize_vault_access(
            identity.identity_id,
            vault,
            permission,
        )

        return vault

    def permission_for(
        vault_id: str,
        action: str,
    ) -> str:
        if vault_id == identity.personal_vault:
            return f"personal.{action}"

        if vault_id in organization_vault_ids:
            return f"organization.{action}"

        raise RuntimeError(
            "The requested vault is outside this identity's scope."
        )

    def decide_memory_proposal(
        vault_id: str,
        proposal_id: str,
        decision: str,
    ) -> dict:
        authorize_vault(
            vault_id,
            permission_for(vault_id, "memory.approve"),
        )

        return approval_manager.decide(
            vault_id=vault_id,
            proposal_id=proposal_id,
            actor_id=identity.identity_id,
            decision=decision,
        )

    # Transport configuration.
    transport = os.environ.get(
        "KOBOG_MCP_TRANSPORT",
        "stdio",
    ).strip().lower()

    host = os.environ.get(
        "KOBOG_MCP_HOST",
        "127.0.0.1",
    ).strip()

    port = int(
        os.environ.get(
            "KOBOG_MCP_PORT",
            "8000",
        )
    )

    mount_path = os.environ.get(
        "KOBOG_MCP_PATH",
        "/mcp",
    ).strip()

    stateless_http = get_bool_env(
        "KOBOG_MCP_STATELESS_HTTP",
        False,
    )

    # Browser CORS configuration.
    allowed_origins = get_csv_env(
        "KOBOG_CORS_ORIGINS",
        "http://localhost:5173",
    )

    if transport not in {"stdio", "sse", "streamable-http"}:
        raise RuntimeError(
            f"Unsupported MCP transport: {transport}"
        )

    if not mount_path.startswith("/"):
        raise RuntimeError(
            "KOBOG_MCP_PATH must start with '/'."
        )

    if transport == "streamable-http" and not allowed_origins:
        raise RuntimeError(
            "KOBOG_CORS_ORIGINS must contain at least one "
            "allowed browser origin."
        )

    mcp = FastMCP(
        "KOBOG Memory",
        host=host,
        port=port,
        streamable_http_path=mount_path,
        stateless_http=stateless_http,
    )

    @mcp.tool()
    def get_current_identity() -> dict:
        """Return the trusted identity and role assigned to this server."""

        role = identity_registry.get_role(identity.identity_id)

        return {
            "identity_id": identity.identity_id,
            "name": identity.name,
            "organization_id": identity.organization,
            "organization": organization.name,
            "role": identity.role,
            "personal_vault": identity.personal_vault,
            "agent_id": identity.agent_id,
            "enabled": identity.enabled,
            "permissions": sorted(role.permissions),
        }

    @mcp.tool()
    def get_agent_context() -> dict:
        """Return the trusted runtime context for this authenticated agent."""

        return context_builder.build().to_dict()

    @mcp.tool()
    def list_accessible_vaults() -> list[dict]:
        """List vaults assigned to this identity's server instance."""

        return [
            {
                "vault_id": vault.vault_id,
                "name": vault.name,
                "organization": vault.organization,
            }
            for vault in vault_manager.list_accessible_vaults()
        ]

    @mcp.tool()
    def search_approved_memory(
        vault_id: str,
        query: str,
        limit: int = 20,
    ) -> list[dict]:
        """Search approved memory in an authorized vault."""

        authorize_vault(
            vault_id,
            permission_for(vault_id, "memory.read"),
        )

        results = reader.search_approved(
            vault_id=vault_id,
            query=query,
            limit=limit,
        )

        return [asdict(result) for result in results]

    @mcp.tool()
    def read_approved_memory(
        vault_id: str,
        relative_path: str,
    ) -> str:
        """Read an approved Markdown memory note."""

        authorize_vault(
            vault_id,
            permission_for(vault_id, "memory.read"),
        )

        return reader.read_note(
            vault_id=vault_id,
            relative_path=relative_path,
        )

    @mcp.tool()
    def submit_memory_proposal(
        vault_id: str,
        title: str,
        content: str,
        reason: str,
        source: str = "hermes",
        memory_type: str = "operational",
        access: str = "internal",
        derived_from: list[str] | None = None,
        department: str | None = None,
        project: str | None = None,
        tags: list[str] | None = None,
        author: str | None = None,
        review_date: str | None = None,
        related: list[str] | None = None,
        source_url: str | None = None,
    ) -> dict:
        """Submit a memory proposal for human review. Does not approve it."""

        authorize_vault(
            vault_id,
            permission_for(vault_id, "memory.propose"),
        )

        return proposals.create_proposal(
            vault_id=vault_id,
            title=title,
            content=content,
            reason=reason,
            source=source,
            memory_type=memory_type,
            access=access,
            derived_from=derived_from,
            department=department,
            project=project,
            tags=tags,
            author=author,
            review_date=review_date,
            related=related,
            source_url=source_url,
        )

    @mcp.tool()
    def approve_memory_proposal(
        vault_id: str,
        proposal_id: str,
    ) -> dict:
        """Approve a pending proposal if this identity has approval permission."""

        return decide_memory_proposal(
            vault_id=vault_id,
            proposal_id=proposal_id,
            decision="approve",
        )

    @mcp.tool()
    def reject_memory_proposal(
        vault_id: str,
        proposal_id: str,
    ) -> dict:
        """Reject a pending proposal if this identity has approval permission."""

        return decide_memory_proposal(
            vault_id=vault_id,
            proposal_id=proposal_id,
            decision="reject",
        )

    @mcp.tool()
    def discover_available_skills() -> list[dict]:
        """Discover active skills available to this identity."""

        skills = skill_registry.discover_skills()

        return [
            {
                "skill_id": skill.skill_id,
                "name": skill.name,
                "description": skill.description,
                "version": skill.version,
                "owner": skill.owner,
                "scope": skill.scope,
                "status": skill.status,
                "required_permissions": list(
                    skill.required_permissions
                ),
            }
            for skill in skills
        ]

    @mcp.tool()
    def read_skill_instructions(
        skill_id: str,
    ) -> str:
        """Retrieve instructions for an active skill available to this identity."""

        return skill_registry.read_skill(skill_id)

    # Store transport settings for the entry point.
    mcp._kobog_transport = transport
    mcp._kobog_host = host
    mcp._kobog_port = port
    mcp._kobog_allowed_origins = allowed_origins

    return mcp


def main() -> None:
    server = create_server()
    transport = server._kobog_transport

    if transport == "stdio":
        server.run(transport="stdio")

    elif transport == "sse":
        server.run(transport="sse")

    elif transport == "streamable-http":
        # Build the FastMCP Starlette application.
        app = server.streamable_http_app()

        # Allow the configured frontend origin to communicate with MCP.
        app.add_middleware(
            CORSMiddleware,
            allow_origins=server._kobog_allowed_origins,
            allow_methods=[
                "GET",
                "POST",
                "DELETE",
                "OPTIONS",
            ],
            allow_headers=[
                "Accept",
                "Authorization",
                "Content-Type",
                "Last-Event-ID",
                "MCP-Protocol-Version",
                "Mcp-Session-Id",
            ],
            expose_headers=[
                "Mcp-Session-Id",
                "Mcp-Protocol-Version",
            ],
            allow_credentials=False,
            max_age=600,
        )

        uvicorn.run(
            app,
            host=server._kobog_host,
            port=server._kobog_port,
            log_level="info",
        )


if __name__ == "__main__":
    main()
