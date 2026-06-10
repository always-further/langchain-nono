#!/usr/bin/env python3
"""API key protection via proxy credential injection.

The proxy can load a real credential from the host OS keyring and inject it
into outbound requests. The sandboxed child receives a route-scoped phantom
token, not the real host credential.

This example uses a local HTTP upstream so it does not need OpenSSL, a public
network service, requests, or the OpenAI SDK. To see a successful injected
Authorization header, store a real value in the host OS keyring under the
account name "openai-key"; without that entry, the proxy fails closed before
forwarding the request.
"""

from __future__ import annotations

import json
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from langchain_nono import InjectMode, NonoSandbox, ProxyConfig, RouteConfig


class HeaderCaptureServer(ThreadingHTTPServer):
    """HTTP server that records the latest Authorization header."""

    def __init__(self, server_address: tuple[str, int]) -> None:
        """Create a capture server."""
        super().__init__(server_address, HeaderCaptureHandler)
        self.last_authorization: str | None = None
        self.last_path: str | None = None


class HeaderCaptureHandler(BaseHTTPRequestHandler):
    """Record request headers and return a small JSON response."""

    server: HeaderCaptureServer

    def do_GET(self) -> None:
        """Handle a probe request from the proxy."""
        authorization = self.headers.get("Authorization")
        self.server.last_authorization = authorization
        self.server.last_path = self.path

        body = json.dumps(
            {
                "authorization_present": authorization is not None,
                "path": self.path,
            }
        ).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        """Silence default request logging for cleaner example output."""


def child_env_state(sandbox: NonoSandbox, name: str) -> str:
    """Return whether the sandboxed child can see an environment variable."""
    result = sandbox.execute(f'test -n "${{{name}:-}}" && echo present || echo absent')
    return result.output.strip()


def main() -> None:
    """Show credential injection without exposing a host API key env var."""
    with tempfile.TemporaryDirectory(prefix="langchain-nono-") as workspace:
        upstream = HeaderCaptureServer(("127.0.0.1", 0))
        upstream_thread = threading.Thread(
            target=upstream.serve_forever,
            name="credential-injection-upstream",
            daemon=True,
        )
        upstream_thread.start()

        route = RouteConfig(
            prefix="/openai",
            upstream=f"http://127.0.0.1:{upstream.server_port}",
            credential_key="openai-key",
            inject_mode=InjectMode.HEADER,
            inject_header="Authorization",
            credential_format="Bearer {}",
            env_var="OPENAI_API_KEY",
        )
        config = ProxyConfig(allowed_hosts=["127.0.0.1"], routes=[route])

        print("1. Creating sandbox with credential injection proxy")
        print(f"   route: {route.prefix} -> {route.upstream}")
        print(f"   credential_key: {route.credential_key}\n")

        sandbox = NonoSandbox(
            working_dir=workspace,
            proxy_config=config,
            block_network=True,
        )

        try:
            print("2. What the sandboxed child sees")
            print(f"   OPENAI_API_KEY: {child_env_state(sandbox, 'OPENAI_API_KEY')}")
            base_url = sandbox.execute('printf "%s" "$OPENAI_BASE_URL"').output.strip()
            print(f"   OPENAI_BASE_URL: {base_url}\n")

            print("3. Calling the local upstream through the proxy")
            result = sandbox.execute(
                "curl -sS "
                '-H "Authorization: Bearer ${OPENAI_API_KEY}" '
                '"${OPENAI_BASE_URL}/inspect" 2>&1 || true'
            )
            print(f"   exit_code: {result.exit_code}")
            print(f"   response: {result.output.strip()}\n")

            print("4. What the upstream observed")
            if upstream.last_authorization is None:
                print("   Authorization header: absent")
                print(
                    "   Result: no keyring credential was available, so the proxy failed closed"
                )
            else:
                print("   Authorization header: present")
                print(
                    "   Result: proxy swapped the phantom token for the real credential"
                )
            print(f"   Upstream path: {upstream.last_path}\n")

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
            upstream.shutdown()
            upstream.server_close()
            upstream_thread.join(timeout=1)
            print("\n6. Proxy shut down.")


if __name__ == "__main__":
    main()
