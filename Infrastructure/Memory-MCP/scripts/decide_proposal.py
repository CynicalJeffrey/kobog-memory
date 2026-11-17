import argparse
import json
import os
import sys
from pathlib import Path

from kobog_memory.config import load_config
from kobog_memory.core.vault_manager import VaultManager
from kobog_memory.governance.approval import (
    ApprovalError,
    MemoryApprovalManager,
)


ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--vault-id", required=True)
    parser.add_argument("--proposal-id", required=True)
    parser.add_argument("--actor-id", required=True)
    parser.add_argument(
        "--decision",
        required=True,
        choices=["approve", "reject"],
    )
    args = parser.parse_args()

    admin_ids = {
        item.strip()
        for item in os.environ.get(
            "KOBOG_ADMIN_TELEGRAM_IDS", ""
        ).split(",")
        if item.strip()
    }

    if not admin_ids:
        print(
            "KOBOG_ADMIN_TELEGRAM_IDS is not configured.",
            file=sys.stderr,
        )
        return 1

    try:
        config = load_config(ROOT / "config" / "vaults.yaml")

        vault_manager = VaultManager(
            config,
            allowed_vault_ids=set(config.vaults.keys()),
        )

        approval_manager = MemoryApprovalManager(
            vault_manager=vault_manager,
            audit_directory=ROOT / "data" / "audit",
            administrator_ids=admin_ids,
        )

        result = approval_manager.decide(
            vault_id=args.vault_id,
            proposal_id=args.proposal_id,
            actor_id=args.actor_id,
            decision=args.decision,
        )

        print(json.dumps(result))
        return 0

    except (ApprovalError, Exception) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
