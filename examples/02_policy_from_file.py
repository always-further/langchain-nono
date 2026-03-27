#!/usr/bin/env python3
"""Load a policy file and show allowed and denied behavior."""

from __future__ import annotations

import platform
from pathlib import Path

from langchain_nono import NonoSandbox, describe_execute_failure


def explain_exec_result(label: str, exit_code: int, output: str) -> None:
    """Print a clearer explanation for sandbox execution results."""
    print(label)
    print(f"  exit_code: {exit_code}")
    cleaned = output.strip()
    message = describe_execute_failure(exit_code, output)
    if message is not None:
        print(f"  sandbox_message: {message}")
        print(f"  raw_output: {cleaned or '<no output>'}")
        return
    print(cleaned or "<no output>")


def main() -> None:
    """Run a realistic sandboxed task using a policy document from disk."""
    example_dir = Path(__file__).parent
    root = Path("/tmp/langchain-nono-demo")
    workspace = root / "workspace"
    references = root / "references"
    secrets = root / "secrets"

    workspace.mkdir(parents=True, exist_ok=True)
    references.mkdir(parents=True, exist_ok=True)
    secrets.mkdir(parents=True, exist_ok=True)

    (references / "runbook.txt").write_text(
        "Deploy checklist:\n1. Run tests\n2. Build artifacts\n3. Roll out gradually\n"
    )
    (secrets / "credentials.txt").write_text("token=prod-credential\n")

    policy_groups = ["workspace_rw", "reference_read"]
    if platform.system() == "Darwin":
        policy_groups.append("secrets_deny")

    sandbox = NonoSandbox(
        working_dir=str(workspace),
        policy_json=(example_dir / "policy_example.json").read_text(),
        policy_groups=policy_groups,
        block_network=True,
    )

    allowed = sandbox.execute(
        "awk 'NR<=2 {print}' ../references/runbook.txt > plan.txt && printf '4. Monitor metrics\\n' >> plan.txt && cat plan.txt"
    )
    denied = sandbox.execute("cat ../secrets/credentials.txt")

    print("Policy groups:", ", ".join(policy_groups))
    print()
    explain_exec_result("Allowed workflow:", allowed.exit_code, allowed.output)
    print()
    if platform.system() == "Darwin":
        label = "Denied by explicit policy deny.access:"
    else:
        label = "Denied because the policy never grants access to secrets:"
        print("  Linux note: overlapping deny.access rules are rejected by nono/Landlock.")
    explain_exec_result(label, denied.exit_code, denied.output)


if __name__ == "__main__":
    main()
