"""Unit tests for NonoSandbox backend."""

from __future__ import annotations

import os
import tempfile

import pytest

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
