#!/usr/bin/env python3
"""Resolve proxy configuration from a policy JSON file.

Instead of manually constructing a ProxyConfig, the proxy domain
allowlist and connection limits can be defined in a nono policy
document and resolved by group name.

This example loads the proxy_web_demo group from policy_example.json
which allows only example.com through the proxy.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from langchain_nono import NonoSandbox


def main() -> None:
    """Resolve proxy config from policy and run a sandboxed command."""
    example_dir = Path(__file__).parent
    policy_json = (example_dir / "policy_example.json").read_text()

    print("1. Resolving proxy config from policy group 'proxy_web_demo'")
    proxy_config = NonoSandbox.resolve_proxy_from_policy(
        policy_json, ["proxy_web_demo"]
    )
    if proxy_config is None:
        print("   No proxy configuration found in policy")
        return

    print(f"   Allowed hosts: {proxy_config.allowed_hosts}")
    print()

    with tempfile.TemporaryDirectory(prefix="langchain-nono-") as workspace:
        print("2. Creating sandbox with policy-resolved proxy\n")
        sandbox = NonoSandbox(
            working_dir=workspace,
            proxy_config=proxy_config,
            block_network=True,
        )

        try:
            # Allowed domain
            print("3. Request to example.com (allowed by policy)")
            allowed = sandbox.execute(
                "curl -sf -o /dev/null -w '%{http_code}' http://example.com 2>&1 || true"
            )
            print(f"   exit_code: {allowed.exit_code}")
            print(f"   output: {allowed.output.strip()}\n")

            # Blocked domain
            print("4. Request to evil.com (blocked -- not in policy)")
            blocked = sandbox.execute(
                "curl -sf -o /dev/null -w '%{http_code}' http://evil.com 2>&1 || true"
            )
            print(f"   exit_code: {blocked.exit_code}")
            print(f"   output: {blocked.output.strip()}\n")

            # Audit trail
            print("5. Network audit trail")
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
            print("\n6. Proxy shut down.")


if __name__ == "__main__":
    main()
