"""Unit tests for NonoSandbox backend."""

from __future__ import annotations

import json
import os
import tempfile
from types import SimpleNamespace

import pytest
from nono_py import ProxyConfig

from langchain_nono import NonoSandbox


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
        result = sandbox.execute("cat /etc/passwd")
        assert result.exit_code != 0

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

    def test_proxy_env_vars_are_injected(
        self, monkeypatch: pytest.MonkeyPatch, workdir: str
    ) -> None:
        """Proxy and credential env vars are passed to sandboxed_exec."""
        captured: dict[str, object] = {}

        class FakeProxyHandle:
            def env_vars(self) -> dict[str, str]:
                return {"HTTP_PROXY": "http://127.0.0.1:1234"}

            def credential_env_vars(self) -> dict[str, str]:
                return {"OPENAI_API_KEY": "PHANTOM_TOKEN"}

            def drain_audit_events(self) -> list[dict[str, object]]:
                return [{"decision": "allow", "target": "example.com"}]

            def shutdown(self) -> None:
                captured["shutdown"] = True

        def fake_start_proxy(config: ProxyConfig) -> FakeProxyHandle:
            captured["proxy_config"] = config
            return FakeProxyHandle()

        def fake_sandboxed_exec(**kwargs):
            captured["env"] = kwargs["env"]
            return SimpleNamespace(stdout=b"ok\n", stderr=b"", exit_code=0)

        monkeypatch.setattr("langchain_nono.sandbox.start_proxy", fake_start_proxy)
        monkeypatch.setattr(
            "langchain_nono.sandbox.sandboxed_exec",
            fake_sandboxed_exec,
        )

        sandbox = NonoSandbox(
            working_dir=workdir,
            proxy_config=ProxyConfig(allowed_hosts=["example.com"]),
        )

        result = sandbox.execute("echo ok")

        assert result.exit_code == 0
        assert captured["env"] == [
            ("HTTP_PROXY", "http://127.0.0.1:1234"),
            ("OPENAI_API_KEY", "PHANTOM_TOKEN"),
        ]
        assert sandbox.drain_network_audit_events() == [
            {"decision": "allow", "target": "example.com"}
        ]
        sandbox.shutdown_proxy()
        assert captured["shutdown"] is True


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

            def save_session_metadata(self, meta):
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

        sandbox.save_session_metadata("test-meta")
        assert captured["meta"] == "test-meta"

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
        with pytest.raises(RuntimeError, match="snapshot support is not configured"):
            sandbox.save_session_metadata("meta")


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
