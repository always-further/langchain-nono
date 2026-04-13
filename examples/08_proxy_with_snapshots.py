#!/usr/bin/env python3
"""Full supervisor flow: proxy + sandbox + snapshots + session metadata.

Demonstrates the complete orchestration pattern:

  1. Start a domain-filtering proxy
  2. Take a baseline snapshot of the workspace
  3. Run sandboxed commands (network + filesystem)
  4. Capture an incremental snapshot and audit events
  5. Build and save session metadata with Merkle roots
  6. Roll back the workspace to its baseline state
"""

from __future__ import annotations

import os
import tempfile

from langchain_nono import (
    ExclusionConfig,
    NonoSandbox,
    ProxyConfig,
    SessionMetadata,
)


def main() -> None:
    """Run the full supervisor workflow."""
    with (
        tempfile.TemporaryDirectory(prefix="langchain-nono-session-") as session_dir,
        tempfile.TemporaryDirectory(prefix="langchain-nono-work-") as workspace,
    ):
        print("=== Supervisor: proxy + sandbox + snapshots ===\n")

        # --- 1. Create sandbox with proxy and snapshot support ---
        print("1. Creating sandbox with proxy and snapshot support")
        sandbox = NonoSandbox(
            working_dir=workspace,
            proxy_config=ProxyConfig(allowed_hosts=["example.com"]),
            snapshot_session_dir=session_dir,
            snapshot_exclusion=ExclusionConfig(use_gitignore=False),
            block_network=True,
        )
        print("   Proxy: example.com allowed")
        print(f"   Snapshots: tracking {workspace}\n")

        # --- 2. Seed workspace and take baseline ---
        print("2. Setting up workspace")
        sandbox.execute("echo 'initial data' > data.txt")
        print("   Created: data.txt\n")

        print("3. Taking baseline snapshot")
        baseline = sandbox.create_snapshot_baseline()
        print(f"   Merkle root: {baseline.merkle_root.hex()[:32]}...\n")

        # --- 3. Run agent commands ---
        print("4. Running sandboxed agent commands")

        # Modify workspace
        sandbox.execute("echo 'modified by agent' > data.txt")
        sandbox.execute("echo 'agent output' > results.txt")
        print("   Modified data.txt, created results.txt")

        # Make a network request through the proxy
        net_result = sandbox.execute(
            "curl -sf -o /dev/null http://example.com 2>&1 || true"
        )
        print(f"   Network request exit_code: {net_result.exit_code}\n")

        # --- 4. Incremental snapshot ---
        print("5. Taking incremental snapshot")
        manifest, changes = sandbox.create_snapshot_incremental()
        print(f"   Merkle root: {manifest.merkle_root.hex()[:32]}...")
        print(f"   Changes: {len(changes)}")
        for change in changes:
            print(f"     {change.change_type}: {os.path.basename(change.path)}")
        print()

        # --- 5. Collect audit events ---
        print("6. Network audit trail")
        events = sandbox.drain_network_audit_events()
        print(f"   {len(events)} event(s) recorded")
        for event in events:
            decision = event["decision"]
            target = event["target"]
            mode = event["mode"]
            print(f"     [{decision}] {mode} -> {target}")
        print()

        # --- 6. Build and save session metadata ---
        print("7. Saving session metadata")
        meta = SessionMetadata(
            session_id="langchain-nono-demo-001",
            command=["bash", "-c", "agent workflow"],
            tracked_paths=[workspace],
        )
        meta.exit_code = 0
        meta.snapshot_count = sandbox.snapshot_count()
        meta.add_merkle_root(baseline.merkle_root)
        meta.add_merkle_root(manifest.merkle_root)
        meta.set_network_events(events)
        sandbox.save_session_metadata(meta)
        print(f"   Session: {meta.session_id}")
        print(f"   Merkle roots: {len(meta.merkle_roots)}")
        print(f"   Network events: {len(events)}\n")

        # Verify we can load it back
        loaded = NonoSandbox.load_session_metadata(session_dir)
        print(f"   Loaded back: session_id={loaded.session_id}")
        print()

        # --- 7. Roll back ---
        print("8. Rolling back to baseline")
        applied = sandbox.restore_snapshot(0)
        print(f"   Applied {len(applied)} change(s)")

        data_check = sandbox.execute("cat data.txt")
        print(f"   data.txt: {data_check.output.strip()!r}")
        results_check = sandbox.execute(
            "test -f results.txt && echo exists || echo missing"
        )
        print(f"   results.txt: {results_check.output.strip()}\n")

        # --- 8. Cleanup ---
        sandbox.shutdown_proxy()
        print("9. Proxy shut down.")
        print("\n=== Complete ===")


if __name__ == "__main__":
    main()
