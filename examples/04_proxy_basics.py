#!/usr/bin/env python3
"""Proxy domain filtering with NonoSandbox.

Demonstrates starting a network proxy that allows only specific domains,
running commands through it, and inspecting the audit trail.

The proxy is started automatically when proxy_config is passed to the
sandbox constructor. All execute() calls receive the proxy environment
variables transparently -- no extra wiring needed.
"""

from __future__ import annotations

import tempfile

from langchain_nono import NonoSandbox, ProxyConfig


def main() -> None:
    """Run commands through a domain-filtering proxy."""
    with tempfile.TemporaryDirectory(prefix="langchain-nono-") as workspace:
        print("1. Creating sandbox with proxy (only example.com allowed)\n")

        sandbox = NonoSandbox(
            working_dir=workspace,
            proxy_config=ProxyConfig(allowed_hosts=["example.com"]),
            block_network=True,
        )

        try:
            # Allowed: example.com is in the allowlist
            print("2. Attempting request to example.com (allowed)")
            allowed = sandbox.execute(
                "curl -sf -o /dev/null -w '%{http_code}' http://example.com 2>&1 || true"
            )
            print(f"   exit_code: {allowed.exit_code}")
            print(f"   output: {allowed.output.strip()}\n")

            # Blocked: evil.com is not in the allowlist
            print("3. Attempting request to evil.com (blocked)")
            blocked = sandbox.execute(
                "curl -sf -o /dev/null -w '%{http_code}' http://evil.com 2>&1 || true"
            )
            print(f"   exit_code: {blocked.exit_code}")
            print(f"   output: {blocked.output.strip()}\n")

            # Inspect the audit trail
            print("4. Network audit trail")
            events = sandbox.drain_network_audit_events()
            print(f"   {len(events)} event(s) recorded")
            for event in events:
                decision = event["decision"]
                target = event["target"]
                mode = event["mode"]
                reason = event.get("reason")
                suffix = f" ({reason})" if reason else ""
                print(f"   [{decision}] {mode} -> {target}{suffix}")

        finally:
            sandbox.shutdown_proxy()
            print("\n5. Proxy shut down.")


if __name__ == "__main__":
    main()
