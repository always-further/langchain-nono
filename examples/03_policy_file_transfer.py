#!/usr/bin/env python3
"""Show policy-aware upload and download behavior with clearer errors."""

from __future__ import annotations

from pathlib import Path

from langchain_nono import NonoSandbox, describe_file_transfer_error


def main() -> None:
    """Upload into an allowed workspace and show denied reads elsewhere."""
    example_dir = Path(__file__).parent
    root = Path("/tmp/langchain-nono-demo")
    workspace = root / "workspace"
    references = root / "references"
    secrets = root / "secrets"

    workspace.mkdir(parents=True, exist_ok=True)
    references.mkdir(parents=True, exist_ok=True)
    secrets.mkdir(parents=True, exist_ok=True)

    (references / "api_spec.txt").write_text("POST /tasks\nGET /tasks/{id}\n")
    (secrets / "billing.env").write_text("STRIPE_KEY=live-secret\n")

    sandbox = NonoSandbox(
        working_dir=str(workspace),
        policy_json=(example_dir / "policy_example.json").read_text(),
        policy_groups=["workspace_rw", "reference_read"],
        block_network=True,
    )

    allowed_upload = sandbox.upload_files(
        [(str(workspace / "draft.md"), b"# Draft Plan\nReview API spec first.\n")]
    )[0]
    denied_upload = sandbox.upload_files(
        [(str(secrets / "overwrite.env"), b"should not be allowed\n")]
    )[0]

    allowed_download = sandbox.download_files([str(references / "api_spec.txt")])[0]
    denied_download = sandbox.download_files([str(secrets / "billing.env")])[0]

    print("Allowed upload to workspace:")
    print(f"  path: {allowed_upload.path}")
    print(f"  result: {describe_file_transfer_error(allowed_upload.error)}")
    print()

    print("Denied upload to secrets:")
    print(f"  path: {denied_upload.path}")
    print(f"  result: {describe_file_transfer_error(denied_upload.error)}")
    print()

    print("Allowed download from references:")
    print(f"  path: {allowed_download.path}")
    print(f"  result: {describe_file_transfer_error(allowed_download.error)}")
    print("  content: {allowed_download.content.decode().strip()}")
    print()

    print("Denied download from secrets:")
    print(f"  path: {denied_download.path}")
    print(f"  result: {describe_file_transfer_error(denied_download.error)}")


if __name__ == "__main__":
    main()
