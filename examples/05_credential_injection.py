#!/usr/bin/env python3
"""API key protection via proxy credential injection.

Demonstrates the core security feature of the nono proxy: sandboxed code
never sees real API keys. Instead, the proxy:

  1. Loads real credentials from the host's OS keyring (credential_key).
  2. Gives the child process a phantom token via environment variables.
  3. Intercepts outbound requests and transparently swaps the phantom
     token for the real credential before forwarding upstream.

The sandboxed agent only ever sees the phantom token. Even if the agent
is compromised, the real API key cannot be exfiltrated.

This example uses a fictional "openai-key" credential_key. To run with
a real key, store it in your OS keyring under that account name.

InjectMode options:
  - HEADER:      Inject as an HTTP header (e.g. Authorization: Bearer <key>)
  - QUERY_PARAM: Append as a URL query parameter (e.g. ?key=<key>)
  - BASIC_AUTH:  Use HTTP Basic Authentication
  - URL_PATH:    Replace a path pattern with the credential
"""

from __future__ import annotations

import tempfile

from langchain_nono import (
    InjectMode,
    NonoSandbox,
    ProxyConfig,
    RouteConfig,
)


def main() -> None:
    """Show credential injection with phantom token swapping."""
    with tempfile.TemporaryDirectory(prefix="langchain-nono-") as workspace:
        # Configure a reverse-proxy route for OpenAI.
        # The proxy will:
        #   - Match requests to /openai/* and forward them to api.openai.com
        #   - Swap the phantom OPENAI_API_KEY token for the real credential
        #     loaded from the OS keyring under "openai-key"
        #   - Inject it as an Authorization: Bearer <real-key> header
        route = RouteConfig(
            prefix="/openai",
            upstream="https://api.openai.com",
            credential_key="openai-key",
            inject_mode=InjectMode.HEADER,
            inject_header="Authorization",
            credential_format="Bearer {}",
        )

        print("1. Route configuration")
        print(f"   prefix:            {route.prefix}")
        print(f"   upstream:          {route.upstream}")
        print(f"   credential_key:    {route.credential_key}")
        print(f"   inject_mode:       {route.inject_mode}")
        print(f"   inject_header:     {route.inject_header}")
        print(f"   credential_format: {route.credential_format}")
        print()

        config = ProxyConfig(
            allowed_hosts=["api.openai.com"],
            routes=[route],
        )

        print("2. Creating sandbox with credential injection proxy\n")
        sandbox = NonoSandbox(
            working_dir=workspace,
            proxy_config=config,
            block_network=True,
        )

        try:
            # The child sees a phantom token, not the real API key.
            # Print the OPENAI_API_KEY env var to prove it's a phantom.
            print("3. Checking what the sandboxed child sees")
            result = sandbox.execute('echo "OPENAI_API_KEY=$OPENAI_API_KEY"')
            for line in result.output.strip().splitlines():
                print(f"   {line}")
            print()

            # Also show the base URL override that routes through the proxy.
            print("4. Checking base URL override")
            result = sandbox.execute('echo "OPENAI_BASE_URL=$OPENAI_BASE_URL"')
            for line in result.output.strip().splitlines():
                print(f"   {line}")
            print()

            # Attempt an API call through the proxy.
            # The proxy would swap the phantom token for the real key.
            # (This will fail without a real keyring entry, but the proxy
            # still logs the attempt as an audit event.)
            print("5. Attempting API call through proxy")
            result = sandbox.execute(
                "curl -sf http://localhost:${NONO_PROXY_PORT}/openai/v1/models "
                "-H 'Authorization: Bearer ${OPENAI_API_KEY}' 2>&1 || true"
            )
            print(f"   exit_code: {result.exit_code}")
            if result.output.strip():
                for line in result.output.strip().splitlines()[:5]:
                    print(f"   {line}")
            print()

            # Audit trail shows the request flow
            print("6. Network audit trail")
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
            print("\n7. Proxy shut down.")

        print()
        print("Security summary:")
        print("  - Real API key: stored in host OS keyring only")
        print("  - Phantom token: given to sandboxed child via env var")
        print("  - Proxy: transparently swaps phantom -> real on outbound requests")
        print("  - Result: compromised agent cannot exfiltrate real credentials")


if __name__ == "__main__":
    main()
