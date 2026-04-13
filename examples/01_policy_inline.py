#!/usr/bin/env python3
"""Demonstrate a realistic inline policy for an agent workspace."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from langchain_nono import NonoSandbox, describe_execute_failure


def explain_exec_result(label: str, exit_code: int | None, output: str) -> None:
    """Print a clearer explanation for sandbox execution results."""
    print(label)
    print(f"  exit_code: {exit_code}")
    cleaned = output.strip()
    if exit_code is None:
        print(f"  raw_output: {cleaned or '<no output>'}")
        return
    message = describe_execute_failure(exit_code, output)
    if message is not None:
        print(f"  sandbox_message: {message}")
        print(f"  raw_output: {cleaned or '<no output>'}")
        return
    print(cleaned or "<no output>")


def main() -> None:
    """Run a small research-style task with explicit allow and deny behavior."""
    with tempfile.TemporaryDirectory(prefix="langchain-nono-") as root:
        root_path = Path(root)
        workspace = root_path / "workspace"
        references = root_path / "references"
        secrets = root_path / "secrets"

        workspace.mkdir()
        references.mkdir()
        secrets.mkdir()

        (references / "design_notes.md").write_text(
            "# Design Notes\nUse structured logging and retry transient failures.\n"
        )
        (secrets / "prod.env").write_text("API_KEY=super-secret-value\n")

        policy_json = json.dumps(
            {
                "groups": {
                    "workspace_rw": {
                        "description": "Agent can modify its working directory",
                        "allow": {"readwrite": [str(workspace)]},
                    },
                    "reference_read": {
                        "description": "Agent can read reference material",
                        "allow": {"read": [str(references)]},
                    },
                }
            }
        )

        sandbox = NonoSandbox(
            working_dir=str(workspace),
            policy_json=policy_json,
            policy_groups=["workspace_rw", "reference_read"],
            block_network=True,
        )

        allowed = sandbox.execute(
            "cat ../references/design_notes.md > summary.txt && printf '\\nReviewed by sandbox\\n' >> summary.txt && cat summary.txt"
        )
        denied = sandbox.execute("cat ../secrets/prod.env")

        explain_exec_result("Allowed workflow:", allowed.exit_code, allowed.output)
        print()
        explain_exec_result(
            "Denied access to ungranted secrets:",
            denied.exit_code,
            denied.output,
        )


if __name__ == "__main__":
    main()
