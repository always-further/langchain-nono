#!/usr/bin/env python3
"""Filesystem snapshots and rollback with NonoSandbox.

Demonstrates content-addressable snapshots: baseline capture, incremental
change detection, dry-run restore diffs, and full workspace rollback.

Each snapshot commits the tracked filesystem state via a Merkle root.
Different states produce different roots, providing a tamper-proof
audit trail of what the agent changed.
"""

from __future__ import annotations

import os
import tempfile

from langchain_nono import ExclusionConfig, NonoSandbox


def main() -> None:
    """Walk through the snapshot lifecycle."""
    with (
        tempfile.TemporaryDirectory(prefix="langchain-nono-session-") as session_dir,
        tempfile.TemporaryDirectory(prefix="langchain-nono-work-") as workspace,
    ):
        print("1. Creating sandbox with snapshot support\n")
        sandbox = NonoSandbox(
            working_dir=workspace,
            snapshot_session_dir=session_dir,
            snapshot_exclusion=ExclusionConfig(
                use_gitignore=False,
                exclude_patterns=["__pycache__", "node_modules"],
                exclude_globs=["*.pyc"],
            ),
        )

        # Seed the workspace with initial files
        sandbox.execute("echo '# My Project' > README.md")
        sandbox.execute("echo '{\"debug\": false}' > config.json")

        # --- Baseline snapshot ---
        print("2. Creating baseline snapshot")
        baseline = sandbox.create_snapshot_baseline()
        print(f"   Merkle root: {baseline.merkle_root.hex()[:32]}...")
        print(f"   Files tracked: {len(baseline.files)}")
        for path, state in sorted(baseline.files.items()):
            print(f"     {os.path.basename(path)}: {state.size} bytes")
        print()

        # --- Agent makes changes ---
        print("3. Simulating agent changes")
        sandbox.execute("echo 'Modified by agent.' >> README.md")
        sandbox.execute("echo 'agent output' > results.txt")
        sandbox.execute("rm config.json")
        print("   Modified README.md, created results.txt, deleted config.json\n")

        # --- Incremental snapshot ---
        print("4. Creating incremental snapshot")
        manifest, changes = sandbox.create_snapshot_incremental()
        print(f"   Merkle root: {manifest.merkle_root.hex()[:32]}...")
        print(f"   Changes detected: {len(changes)}")
        for change in changes:
            delta = (
                f" ({change.size_delta:+d} bytes)"
                if change.size_delta is not None
                else ""
            )
            print(f"     {change.change_type}: {os.path.basename(change.path)}{delta}")
        print()

        # --- Verify Merkle roots differ ---
        print("5. State commitment verification")
        print(f"   Baseline root:    {baseline.merkle_root.hex()[:32]}...")
        print(f"   Incremental root: {manifest.merkle_root.hex()[:32]}...")
        print(f"   Roots differ: {baseline.merkle_root != manifest.merkle_root}")
        print()

        # --- Dry-run restore ---
        print("6. Dry-run restore to baseline")
        diff = sandbox.compute_restore_diff(0)
        print(f"   Changes that would be applied: {len(diff)}")
        for change in diff:
            print(f"     {change.change_type}: {os.path.basename(change.path)}")
        print()

        # --- Actual restore ---
        print("7. Restoring to baseline")
        applied = sandbox.restore_snapshot(0)
        print(f"   Applied {len(applied)} change(s)")

        # Verify the workspace is back to baseline
        readme = sandbox.execute("cat README.md")
        print(f"   README.md: {readme.output.strip()!r}")
        config_check = sandbox.execute(
            "test -f config.json && echo exists || echo missing"
        )
        print(f"   config.json: {config_check.output.strip()}")
        results_check = sandbox.execute(
            "test -f results.txt && echo exists || echo missing"
        )
        print(f"   results.txt: {results_check.output.strip()}")
        print()

        print(f"8. Total snapshots: {sandbox.snapshot_count()}")
        print("\nAll examples completed.")


if __name__ == "__main__":
    main()
