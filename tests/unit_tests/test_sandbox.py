"""Unit tests for NonoSandbox backend."""

from __future__ import annotations

import json
import os
import shlex
import ssl
import tempfile
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import IPv4Address
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from deepagents.backends.protocol import FileDownloadResponse, FileUploadResponse
from nono_py import InjectMode, ProxyConfig, RouteConfig, SessionMetadata

from langchain_nono import NonoSandbox


class _CaptureServer(ThreadingHTTPServer):
    last_path: str | None = None
    last_authorization: str | None = None


class _CaptureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.server.last_path = self.path  # type: ignore[attr-defined]
        self.server.last_authorization = self.headers.get("Authorization")  # type: ignore[attr-defined]
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def _create_localhost_certificate(directory: str) -> tuple[str, str, str]:
    ca_cert_path = Path(directory) / "localhost-ca.crt"
    cert_path = Path(directory) / "localhost.crt"
    key_path = Path(directory) / "localhost.key"

    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "langchain-nono-local-ca")]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(IPv4Address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return str(ca_cert_path), str(cert_path), str(key_path)


@pytest.fixture
def workdir():
    """Provide a temporary working directory."""
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def sandbox(workdir: str) -> NonoSandbox:
    """Create a NonoSandbox with default settings."""
    return NonoSandbox(working_dir=workdir)


class TestNonoSandboxCreation:
    """Tests for sandbox construction."""

    def test_creates_with_defaults(self, workdir: str) -> None:
        """Sandbox can be created with just a working directory."""
        sandbox = NonoSandbox(working_dir=workdir)
        assert sandbox.id is not None
        assert len(sandbox.id) > 0

    def test_unique_ids(self, workdir: str) -> None:
        """Each sandbox instance gets a unique ID."""
        a = NonoSandbox(working_dir=workdir)
        b = NonoSandbox(working_dir=workdir)
        assert a.id != b.id

    def test_negative_timeout_raises(self, workdir: str) -> None:
        """Negative timeout is rejected at construction."""
        with pytest.raises(ValueError, match="timeout must be positive"):
            NonoSandbox(working_dir=workdir, timeout=-1)

    def test_zero_timeout_raises(self, workdir: str) -> None:
        """Zero timeout is rejected at construction."""
        with pytest.raises(ValueError, match="timeout must be positive"):
            NonoSandbox(working_dir=workdir, timeout=0)

    def test_policy_groups_require_policy_json(self, workdir: str) -> None:
        """Policy group names cannot be used without a policy document."""
        with pytest.raises(ValueError, match="policy_groups requires policy_json"):
            NonoSandbox(
                working_dir=workdir,
                policy_groups=["tmp_read"],
            )

    def test_policy_json_requires_groups(self, workdir: str) -> None:
        """Policy documents must specify at least one group to resolve."""
        with pytest.raises(
            ValueError,
            match="policy_json requires at least one policy group",
        ):
            NonoSandbox(
                working_dir=workdir,
                policy_json=json.dumps({"groups": {}}),
            )

    def test_proxy_config_requires_block_network(self, workdir: str) -> None:
        """Proxy filtering must run with direct network blocked."""
        with pytest.raises(
            ValueError, match="proxy_config requires block_network=True"
        ):
            NonoSandbox(
                working_dir=workdir,
                proxy_config=ProxyConfig(allowed_hosts=["example.com"]),
                block_network=False,
            )

    def test_proxy_config_uses_proxy_only_on_linux(
        self, monkeypatch: pytest.MonkeyPatch, workdir: str
    ) -> None:
        """Linux proxy mode uses nono-py's localhost-restricted proxy mode."""
        monkeypatch.setattr("langchain_nono.sandbox.platform.system", lambda: "Linux")

        sandbox = NonoSandbox(
            working_dir=workdir,
            proxy_config=ProxyConfig(allowed_hosts=["example.com"]),
        )
        try:
            assert sandbox.drain_network_audit_events() == []
        finally:
            sandbox.shutdown_proxy()

    def test_proxy_env_vars_are_passed_to_sandboxed_exec(
        self, monkeypatch: pytest.MonkeyPatch, workdir: str
    ) -> None:
        """Proxy env vars are passed through sandboxed_exec's clean env API."""
        captured: dict[str, object] = {}
        monkeypatch.setenv("NONO_HOST_SECRET", "host-secret")

        def fake_sandboxed_exec(**kwargs):
            captured["command"] = kwargs["command"]
            captured["env"] = kwargs["env"]
            captured["inherit_env"] = kwargs["inherit_env"]
            return SimpleNamespace(stdout=b"ok\n", stderr=b"", exit_code=0)

        monkeypatch.setattr(
            "langchain_nono.sandbox.sandboxed_exec",
            fake_sandboxed_exec,
        )

        sandbox = NonoSandbox(
            working_dir=workdir,
            proxy_config=ProxyConfig(allowed_hosts=["example.com"]),
        )
        try:
            result = sandbox.execute("echo ok")
        finally:
            sandbox.shutdown_proxy()

        env = dict(captured["env"])
        assert result.exit_code == 0
        assert captured["command"] == ["/bin/bash", "-c", "echo ok"]
        assert captured["inherit_env"] is False
        http_proxy = urlsplit(env["HTTP_PROXY"])
        https_proxy = urlsplit(env["HTTPS_PROXY"])
        assert http_proxy.scheme == "http"
        assert http_proxy.hostname == "127.0.0.1"
        assert http_proxy.port is not None
        assert https_proxy.scheme == "http"
        assert https_proxy.hostname == "127.0.0.1"
        assert https_proxy.port == http_proxy.port
        assert "NONO_PROXY_TOKEN" in env
        assert "NONO_HOST_SECRET" not in env

    def test_plain_env_is_passed_to_sandboxed_exec_without_inheritance(
        self, monkeypatch: pytest.MonkeyPatch, workdir: str
    ) -> None:
        """Non-proxy execution also uses an explicit sanitized environment."""
        captured: dict[str, object] = {}
        monkeypatch.setenv("NONO_HOST_SECRET", "host-secret")

        def fake_sandboxed_exec(**kwargs):
            captured["env"] = kwargs["env"]
            captured["inherit_env"] = kwargs["inherit_env"]
            return SimpleNamespace(stdout=b"ok\n", stderr=b"", exit_code=0)

        monkeypatch.setattr(
            "langchain_nono.sandbox.sandboxed_exec",
            fake_sandboxed_exec,
        )

        sandbox = NonoSandbox(working_dir=workdir)
        result = sandbox.execute("echo ok")

        env = dict(captured["env"])
        assert result.exit_code == 0
        assert captured["inherit_env"] is False
        assert "PATH" in env
        assert "NONO_HOST_SECRET" not in env

    def test_macos_sets_curl_ca_bundle_without_granting_etc(
        self, monkeypatch: pytest.MonkeyPatch, workdir: str
    ) -> None:
        """macOS curl can use the CA bundle without broad /etc access."""
        captured: dict[str, object] = {}
        monkeypatch.setattr("langchain_nono.sandbox.platform.system", lambda: "Darwin")
        monkeypatch.setattr("langchain_nono.sandbox.os.path.exists", lambda _path: True)

        def fake_sandboxed_exec(**kwargs):
            captured["env"] = kwargs["env"]
            return SimpleNamespace(stdout=b"ok\n", stderr=b"", exit_code=0)

        monkeypatch.setattr(
            "langchain_nono.sandbox.sandboxed_exec",
            fake_sandboxed_exec,
        )

        sandbox = NonoSandbox(working_dir=workdir)
        result = sandbox.execute("echo ok")

        env = dict(captured["env"])
        assert result.exit_code == 0
        assert env["CURL_CA_BUNDLE"] == "/private/etc/ssl/cert.pem"
        assert all(value != "/etc/ssl/cert.pem" for value in env.values())


class TestNonoSandboxExecute:
    """Tests for command execution."""

    def test_simple_echo(self, sandbox: NonoSandbox) -> None:
        """Execute a simple command."""
        result = sandbox.execute("echo hello")
        assert result.exit_code == 0
        assert "hello" in result.output

    def test_exit_code(self, sandbox: NonoSandbox) -> None:
        """Non-zero exit codes are captured."""
        result = sandbox.execute("exit 42")
        assert result.exit_code == 42

    def test_stderr_in_output(self, sandbox: NonoSandbox) -> None:
        """stderr is included in combined output."""
        result = sandbox.execute("echo err >&2")
        assert "err" in result.output
        assert "<stderr>" in result.output

    def test_timeout(self, sandbox: NonoSandbox) -> None:
        """Timeout kills long-running commands."""
        result = sandbox.execute("sleep 60", timeout=1)
        assert result.exit_code == 124

    def test_negative_timeout_in_execute_raises(self, sandbox: NonoSandbox) -> None:
        """Negative timeout in execute() is rejected."""
        with pytest.raises(ValueError, match="timeout must be positive"):
            sandbox.execute("echo hello", timeout=-1)

    def test_sandbox_blocks_forbidden_paths(self, sandbox: NonoSandbox) -> None:
        """Sandbox prevents access to paths outside the capability set."""
        result = sandbox.execute("cat /etc/hosts")
        assert result.exit_code != 0

    def test_sandbox_does_not_grant_private_etc_directory(
        self, sandbox: NonoSandbox
    ) -> None:
        """macOS support files must not imply broad /private/etc access."""
        result = sandbox.execute("test -r /private/etc && echo readable || echo denied")
        assert result.exit_code == 0
        assert result.output.strip() == "denied"

    def test_write_and_read(self, sandbox: NonoSandbox) -> None:
        """Can write and read files in the working directory."""
        result = sandbox.execute("echo content > test.txt && cat test.txt")
        assert result.exit_code == 0
        assert "content" in result.output

    def test_repeated_execution(self, sandbox: NonoSandbox) -> None:
        """Multiple execute calls work."""
        for i in range(3):
            result = sandbox.execute(f"echo {i}")
            assert result.exit_code == 0
            assert str(i) in result.output

    def test_execute_does_not_inherit_host_env(
        self, monkeypatch: pytest.MonkeyPatch, workdir: str
    ) -> None:
        """Host environment variables are not leaked into the child."""
        monkeypatch.setenv("NONO_HOST_SECRET", "host-secret")

        sandbox = NonoSandbox(working_dir=workdir)

        result = sandbox.execute('printf "%s" "${NONO_HOST_SECRET-unset}"')

        assert result.exit_code == 0
        assert result.output == "unset"

    def test_reverse_proxy_route_is_reachable_when_network_blocked(
        self, workdir: str
    ) -> None:
        """Reverse proxy routes remain reachable with direct network blocked."""
        ca_cert_path, cert_path, key_path = _create_localhost_certificate(workdir)
        upstream = _CaptureServer(("127.0.0.1", 0), _CaptureHandler)
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        upstream.socket = ssl_context.wrap_socket(upstream.socket, server_side=True)
        thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        thread.start()

        sandbox = NonoSandbox(
            working_dir=workdir,
            proxy_config=ProxyConfig(
                allowed_hosts=["127.0.0.1"],
                routes=[
                    RouteConfig(
                        prefix="/test",
                        upstream=f"https://127.0.0.1:{upstream.server_port}",
                        tls_ca=ca_cert_path,
                    )
                ],
            ),
            block_network=True,
        )

        try:
            result = sandbox.execute(
                'curl -sf -H "Proxy-Authorization: Bearer ${NONO_PROXY_TOKEN}" ${TEST_BASE_URL}/hello'
            )
            events = sandbox.drain_network_audit_events()
        finally:
            sandbox.shutdown_proxy()
            upstream.shutdown()
            upstream.server_close()
            thread.join(timeout=1)

        assert result.exit_code == 0
        assert result.output.strip() == "ok"
        assert upstream.last_path == "/hello"
        assert any(
            event["mode"] == "reverse"
            and event["decision"] == "allow"
            and event.get("path") == "/hello"
            for event in events
        )

    def test_env_credential_route_injects_real_value_without_exposing_it(
        self, monkeypatch: pytest.MonkeyPatch, workdir: str
    ) -> None:
        """env:// routes load host env credentials and expose only phantom env."""
        monkeypatch.setenv("OPENAI_API_KEY", "demo-real-secret")
        upstream = _CaptureServer(("127.0.0.1", 0), _CaptureHandler)
        thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        thread.start()

        sandbox = NonoSandbox(
            working_dir=workdir,
            proxy_config=ProxyConfig(
                allowed_hosts=["127.0.0.1"],
                routes=[
                    RouteConfig(
                        prefix="/openai",
                        upstream=f"http://127.0.0.1:{upstream.server_port}",
                        credential_key="env://OPENAI_API_KEY",
                        inject_mode=InjectMode.HEADER,
                        inject_header="Authorization",
                        credential_format="Bearer {}",
                        env_var="OPENAI_API_KEY",
                    )
                ],
            ),
            block_network=True,
        )

        try:
            child_secret = sandbox.execute('printf "%s" "$OPENAI_API_KEY"')
            request_script = """
import os
import urllib.request

request = urllib.request.Request(
    os.environ["OPENAI_BASE_URL"] + "/models",
    headers={"Authorization": "Bearer " + os.environ["OPENAI_API_KEY"]},
)
with urllib.request.urlopen(request, timeout=30) as response:
    print(response.read().decode())
"""
            result = sandbox.execute(f"python3 -c {shlex.quote(request_script)}")
        finally:
            sandbox.shutdown_proxy()
            upstream.shutdown()
            upstream.server_close()
            thread.join(timeout=1)

        assert result.exit_code == 0
        assert child_secret.output
        assert child_secret.output != "demo-real-secret"
        assert upstream.last_authorization == "Bearer demo-real-secret"


class TestNonoSandboxFileTransfer:
    """Tests for upload/download operations."""

    def test_upload_file(self, sandbox: NonoSandbox, workdir: str) -> None:
        """Upload writes files within the working directory."""
        real = os.path.realpath(workdir)
        path = os.path.join(real, "uploaded.txt")
        responses = sandbox.upload_files([(path, b"uploaded content")])
        assert len(responses) == 1
        assert responses[0].error is None
        with open(path, "rb") as f:
            assert f.read() == b"uploaded content"

    def test_download_file(self, sandbox: NonoSandbox, workdir: str) -> None:
        """Download reads files within the working directory."""
        real = os.path.realpath(workdir)
        path = os.path.join(real, "to_download.txt")
        with open(path, "wb") as f:
            f.write(b"download me")
        responses = sandbox.download_files([path])
        assert len(responses) == 1
        assert responses[0].content == b"download me"
        assert responses[0].error is None

    def test_download_missing_file(self, sandbox: NonoSandbox, workdir: str) -> None:
        """Download returns error for missing files."""
        real = os.path.realpath(workdir)
        path = os.path.join(real, "nonexistent.txt")
        responses = sandbox.download_files([path])
        assert len(responses) == 1
        assert responses[0].error == "file_not_found"
        assert responses[0].content is None

    def test_upload_invalid_path(self, sandbox: NonoSandbox) -> None:
        """Upload rejects relative paths."""
        responses = sandbox.upload_files([("relative/path.txt", b"data")])
        assert len(responses) == 1
        assert responses[0].error == "invalid_path"

    def test_download_invalid_path(self, sandbox: NonoSandbox) -> None:
        """Download rejects relative paths."""
        responses = sandbox.download_files(["relative/path.txt"])
        assert len(responses) == 1
        assert responses[0].error == "invalid_path"

    def test_download_directory(self, sandbox: NonoSandbox, workdir: str) -> None:
        """Download returns is_directory error for directories."""
        real = os.path.realpath(workdir)
        responses = sandbox.download_files([real])
        assert len(responses) == 1
        assert responses[0].error == "is_directory"

    def test_upload_outside_sandbox_blocked(self, sandbox: NonoSandbox) -> None:
        """Upload to paths outside allowed directories is denied."""
        responses = sandbox.upload_files([("/etc/evil.txt", b"data")])
        assert len(responses) == 1
        assert responses[0].error == "permission_denied"

    def test_download_outside_sandbox_blocked(self, sandbox: NonoSandbox) -> None:
        """Download from paths outside allowed directories is denied."""
        responses = sandbox.download_files(["/etc/passwd"])
        assert len(responses) == 1
        assert responses[0].error == "permission_denied"

    def test_upload_then_execute_reads(
        self, sandbox: NonoSandbox, workdir: str
    ) -> None:
        """Files uploaded by parent are accessible to sandboxed commands."""
        real = os.path.realpath(workdir)
        path = os.path.join(real, "input.txt")
        sandbox.upload_files([(path, b"agent input")])
        result = sandbox.execute(f"cat {path}")
        assert result.exit_code == 0
        assert "agent input" in result.output

    def test_execute_writes_then_download(
        self, sandbox: NonoSandbox, workdir: str
    ) -> None:
        """Files written by sandboxed commands are downloadable."""
        real = os.path.realpath(workdir)
        path = os.path.join(real, "output.txt")
        sandbox.execute(f"echo 'agent output' > {path}")
        responses = sandbox.download_files([path])
        assert len(responses) == 1
        assert responses[0].content is not None
        assert b"agent output" in responses[0].content

    def test_virtual_workspace_root_write_returns_real_workspace_path(
        self, workdir: str
    ) -> None:
        """Deep Agents-style /file paths can resolve into the workspace."""
        real = os.path.realpath(workdir)
        sandbox = NonoSandbox(working_dir=workdir, virtual_workspace_root=True)

        result = sandbox.write("/hello.py", 'print("Hello, World!")\n')

        assert result.error is None
        assert result.path == os.path.join(real, "hello.py")
        run = sandbox.execute(f"python3 {result.path}")
        assert run.exit_code == 0
        assert run.output.strip() == "Hello, World!"

    def test_virtual_workspace_root_upload_download_roundtrip(
        self, workdir: str
    ) -> None:
        """Virtual absolute paths are mapped under the concrete workspace."""
        real = os.path.realpath(workdir)
        sandbox = NonoSandbox(working_dir=workdir, virtual_workspace_root=True)

        upload = sandbox.upload_files([("/notes/todo.txt", b"ship it")])
        download = sandbox.download_files(["/notes/todo.txt"])

        assert upload == [FileUploadResponse(path="/notes/todo.txt", error=None)]
        assert download == [
            FileDownloadResponse(path="/notes/todo.txt", content=b"ship it", error=None)
        ]
        assert os.path.exists(os.path.join(real, "notes", "todo.txt"))

    def test_upload_batch_partial_failure(
        self, sandbox: NonoSandbox, workdir: str
    ) -> None:
        """Batch upload returns per-file results, not all-or-nothing."""
        real = os.path.realpath(workdir)
        good_path = os.path.join(real, "good.txt")
        bad_path = "/etc/evil.txt"
        responses = sandbox.upload_files(
            [
                (good_path, b"good"),
                (bad_path, b"bad"),
            ]
        )
        assert len(responses) == 2
        assert responses[0].error is None
        assert responses[1].error == "permission_denied"

    def test_download_batch_partial_failure(
        self, sandbox: NonoSandbox, workdir: str
    ) -> None:
        """Batch download returns per-file results, not all-or-nothing."""
        real = os.path.realpath(workdir)
        good_path = os.path.join(real, "exists.txt")
        with open(good_path, "wb") as f:
            f.write(b"data")
        bad_path = "/etc/passwd"
        responses = sandbox.download_files([good_path, bad_path])
        assert len(responses) == 2
        assert responses[0].error is None
        assert responses[0].content == b"data"
        assert responses[1].error == "permission_denied"


class TestNonoSandboxModeSeparation:
    """Tests that read/write permissions are enforced separately."""

    def test_read_only_path_blocks_upload(self) -> None:
        """A read-only path cannot be written to via upload_files."""
        with (
            tempfile.TemporaryDirectory() as workdir,
            tempfile.TemporaryDirectory() as ro_dir,
        ):
            sandbox = NonoSandbox(
                working_dir=workdir,
                allow_read=[ro_dir],
            )
            real = os.path.realpath(ro_dir)
            path = os.path.join(real, "should_fail.txt")
            responses = sandbox.upload_files([(path, b"data")])
            assert responses[0].error == "permission_denied"

    def test_write_only_path_blocks_download(self) -> None:
        """A write-only path cannot be read from via download_files."""
        with (
            tempfile.TemporaryDirectory() as workdir,
            tempfile.TemporaryDirectory() as wo_dir,
        ):
            # Create a file in the write-only dir
            real = os.path.realpath(wo_dir)
            path = os.path.join(real, "secret.txt")
            with open(path, "wb") as f:
                f.write(b"secret")

            sandbox = NonoSandbox(
                working_dir=workdir,
                allow_write=[wo_dir],
            )
            responses = sandbox.download_files([path])
            assert responses[0].error == "permission_denied"

    def test_read_only_path_allows_download(self) -> None:
        """A read-only path can be read from via download_files."""
        with (
            tempfile.TemporaryDirectory() as workdir,
            tempfile.TemporaryDirectory() as ro_dir,
        ):
            real = os.path.realpath(ro_dir)
            path = os.path.join(real, "readable.txt")
            with open(path, "wb") as f:
                f.write(b"readable")

            sandbox = NonoSandbox(
                working_dir=workdir,
                allow_read=[ro_dir],
            )
            responses = sandbox.download_files([path])
            assert responses[0].error is None
            assert responses[0].content == b"readable"

    def test_write_only_path_allows_upload(self) -> None:
        """A write-only path can be written to via upload_files."""
        with (
            tempfile.TemporaryDirectory() as workdir,
            tempfile.TemporaryDirectory() as wo_dir,
        ):
            real = os.path.realpath(wo_dir)
            path = os.path.join(real, "writable.txt")

            sandbox = NonoSandbox(
                working_dir=workdir,
                allow_write=[wo_dir],
            )
            responses = sandbox.upload_files([(path, b"written")])
            assert responses[0].error is None
            with open(path, "rb") as f:
                assert f.read() == b"written"

    def test_readwrite_path_allows_both(self) -> None:
        """A read-write path permits both upload and download."""
        with (
            tempfile.TemporaryDirectory() as workdir,
            tempfile.TemporaryDirectory() as rw_dir,
        ):
            real = os.path.realpath(rw_dir)
            path = os.path.join(real, "both.txt")

            sandbox = NonoSandbox(
                working_dir=workdir,
                allow_readwrite=[rw_dir],
            )
            upload = sandbox.upload_files([(path, b"both")])
            assert upload[0].error is None

            download = sandbox.download_files([path])
            assert download[0].error is None
            assert download[0].content == b"both"


class TestNonoSandboxSnapshots:
    """Tests for snapshot and rollback delegation."""

    def test_snapshot_methods_delegate(
        self, monkeypatch: pytest.MonkeyPatch, workdir: str
    ) -> None:
        """Snapshot helpers should call through to SnapshotManager."""
        captured: dict[str, object] = {}

        class FakeSnapshotManager:
            def __init__(
                self,
                *,
                session_dir: str,
                tracked_paths: list[str],
                exclusion,
                max_entries: int,
                max_bytes: int,
            ) -> None:
                captured["session_dir"] = session_dir
                captured["tracked_paths"] = tracked_paths
                captured["exclusion"] = exclusion
                captured["max_entries"] = max_entries
                captured["max_bytes"] = max_bytes

            def create_baseline(self):
                return "baseline"

            def create_incremental(self):
                return ("incremental", ["change"])

            def restore_to(self, snapshot_number: int):
                return [snapshot_number]

            def compute_restore_diff(self, snapshot_number: int):
                return [f"diff-{snapshot_number}"]

            def load_manifest(self, snapshot_number: int):
                return {"number": snapshot_number}

            def save_session_metadata(self, meta: SessionMetadata) -> None:
                captured["meta"] = meta

            def snapshot_count(self) -> int:
                return 2

            @staticmethod
            def load_session_metadata(session_dir: str):
                return f"metadata-from-{session_dir}"

        monkeypatch.setattr(
            "langchain_nono.sandbox.SnapshotManager",
            FakeSnapshotManager,
        )

        sandbox = NonoSandbox(
            working_dir=workdir,
            snapshot_session_dir=os.path.join(workdir, ".nono-snapshots"),
        )

        assert captured["tracked_paths"] == [os.path.realpath(workdir)]
        assert sandbox.create_snapshot_baseline() == "baseline"
        assert sandbox.create_snapshot_incremental() == ("incremental", ["change"])
        assert sandbox.restore_snapshot(0) == [0]
        assert sandbox.compute_restore_diff(0) == ["diff-0"]
        assert sandbox.load_snapshot_manifest(1) == {"number": 1}
        assert sandbox.snapshot_count() == 2

        meta = SessionMetadata(
            session_id="test-session",
            command=["echo", "ok"],
            tracked_paths=[os.path.realpath(workdir)],
        )
        sandbox.save_session_metadata(meta)
        assert captured["meta"] is meta

    def test_load_session_metadata_delegates(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Static load_session_metadata delegates to SnapshotManager."""

        def fake_load(session_dir: str):
            return f"loaded-from-{session_dir}"

        monkeypatch.setattr(
            "langchain_nono.sandbox.SnapshotManager.load_session_metadata",
            staticmethod(fake_load),
        )

        result = NonoSandbox.load_session_metadata("/tmp/test-session")
        assert result == "loaded-from-/tmp/test-session"

    def test_snapshot_methods_require_configuration(self, workdir: str) -> None:
        """Snapshot helpers should fail fast when snapshots are disabled."""
        sandbox = NonoSandbox(working_dir=workdir)

        with pytest.raises(RuntimeError, match="snapshot support is not configured"):
            sandbox.create_snapshot_baseline()
        with pytest.raises(RuntimeError, match="snapshot support is not configured"):
            sandbox.compute_restore_diff(0)
        meta = SessionMetadata(
            session_id="test-session",
            command=["echo", "ok"],
            tracked_paths=[os.path.realpath(workdir)],
        )
        with pytest.raises(RuntimeError, match="snapshot support is not configured"):
            sandbox.save_session_metadata(meta)


class TestNonoSandboxPolicyLoading:
    """Tests for policy-backed capability loading."""

    def test_policy_read_group_allows_download(self) -> None:
        """Policy-derived read grants should be honored by file downloads."""
        with (
            tempfile.TemporaryDirectory() as workdir,
            tempfile.TemporaryDirectory() as policy_dir,
        ):
            real = os.path.realpath(policy_dir)
            path = os.path.join(real, "policy.txt")
            with open(path, "wb") as f:
                f.write(b"policy data")

            sandbox = NonoSandbox(
                working_dir=workdir,
                policy_json=json.dumps(
                    {
                        "groups": {
                            "policy_read": {
                                "description": "Read from policy dir",
                                "allow": {"read": [real]},
                            }
                        }
                    }
                ),
                policy_groups=["policy_read"],
            )

            responses = sandbox.download_files([path])
            assert responses[0].error is None
            assert responses[0].content == b"policy data"

    def test_policy_readwrite_group_allows_upload(self) -> None:
        """Policy-derived read-write grants should be honored by uploads."""
        with (
            tempfile.TemporaryDirectory() as workdir,
            tempfile.TemporaryDirectory() as policy_dir,
        ):
            real = os.path.realpath(policy_dir)
            path = os.path.join(real, "uploaded.txt")

            sandbox = NonoSandbox(
                working_dir=workdir,
                policy_json=json.dumps(
                    {
                        "groups": {
                            "policy_rw": {
                                "description": "Read-write policy dir",
                                "allow": {"readwrite": [real]},
                            }
                        }
                    }
                ),
                policy_groups=["policy_rw"],
            )

            responses = sandbox.upload_files([(path, b"policy write")])
            assert responses[0].error is None
            with open(path, "rb") as f:
                assert f.read() == b"policy write"


class TestNonoSandboxPolicyProxy:
    """Tests for policy-based proxy config resolution."""

    def test_resolve_proxy_from_policy_returns_config(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """resolve_proxy_from_policy returns a ProxyConfig from policy groups."""
        sentinel = ProxyConfig(allowed_hosts=["example.com"])

        class FakePolicy:
            def resolve_proxy_config(self, _groups: list[str]):
                return sentinel

        monkeypatch.setattr(
            "langchain_nono.sandbox.load_policy",
            lambda _json: FakePolicy(),
        )

        result = NonoSandbox.resolve_proxy_from_policy("{}", ["proxy_group"])
        assert result is sentinel

    def test_resolve_proxy_from_policy_returns_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """resolve_proxy_from_policy returns None for non-proxy groups."""

        class FakePolicy:
            def resolve_proxy_config(self, _groups: list[str]):
                return None

        monkeypatch.setattr(
            "langchain_nono.sandbox.load_policy",
            lambda _json: FakePolicy(),
        )

        result = NonoSandbox.resolve_proxy_from_policy("{}", ["no_proxy"])
        assert result is None


class TestNonoSandboxOutputTruncation:
    """Tests for output size limits."""

    def test_large_output_is_truncated(self) -> None:
        """Output exceeding max_output_bytes is truncated."""
        with tempfile.TemporaryDirectory() as workdir:
            sandbox = NonoSandbox(
                working_dir=workdir,
                max_output_bytes=100,
            )
            result = sandbox.execute("python3 -c \"print('x' * 500)\"")
            assert result.truncated is True
            assert len(result.output) <= 100

    def test_small_output_not_truncated(self) -> None:
        """Output within limits is not truncated."""
        with tempfile.TemporaryDirectory() as workdir:
            sandbox = NonoSandbox(working_dir=workdir)
            result = sandbox.execute("echo hello")
            assert result.truncated is False
            assert "hello" in result.output
