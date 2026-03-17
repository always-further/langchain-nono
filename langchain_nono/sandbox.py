"""Nono sandbox backend -- OS-enforced capability-based sandboxing.

Uses Landlock (Linux) and Seatbelt (macOS) to run commands with
kernel-enforced filesystem and network restrictions. Each execute()
call forks a child process, applies the sandbox, then exec's the
command. The parent remains unsandboxed.
"""

from __future__ import annotations

import contextlib
import os
import platform
import sys
from uuid import uuid4

from deepagents.backends.protocol import (
    ExecuteResponse,
    FileDownloadResponse,
    FileUploadResponse,
)
from deepagents.backends.sandbox import BaseSandbox
from nono_py import AccessMode, CapabilitySet, sandboxed_exec

# Minimal system paths required for shell command execution.
# These are read-only and scoped to what bash/coreutils need.
_SYSTEM_PATHS_COMMON = ["/usr", "/bin", "/sbin", "/lib"]
_SYSTEM_PATHS_MACOS = [
    "/private/etc",
    "/private/var/run",
    "/Library/Frameworks",
]

# Maximum bytes of combined stdout+stderr to return from execute().
# Output beyond this limit is discarded and truncated=True is set.
_MAX_OUTPUT_BYTES = 1024 * 1024  # 1 MiB


class NonoSandbox(BaseSandbox):
    """OS-enforced sandbox using Landlock (Linux) and Seatbelt (macOS).

    Each execute() call forks a child process, applies kernel-level
    restrictions, then exec's the command. The parent process remains
    unsandboxed. No containers, VMs, or remote APIs.

    File transfer operations (upload_files/download_files) are confined
    to allowed paths -- the working directory and any paths explicitly
    granted via allow_read/allow_write/allow_readwrite. The access mode
    is enforced: read-only paths cannot be written to via upload_files,
    and write-only paths cannot be read from via download_files.

    Args:
        working_dir: Absolute path to the agent's working directory.
            Granted read-write access inside the sandbox.
        allow_read: Additional paths to grant read-only access.
        allow_write: Additional paths to grant write-only access.
        allow_readwrite: Additional paths to grant read-write access.
        block_network: Whether to block all outbound network access.
        timeout: Default command timeout in seconds (must be positive).
        max_output_bytes: Maximum bytes of output to return from execute().
    """

    def __init__(
        self,
        *,
        working_dir: str,
        allow_read: list[str] | None = None,
        allow_write: list[str] | None = None,
        allow_readwrite: list[str] | None = None,
        block_network: bool = True,
        timeout: int = 30 * 60,
        max_output_bytes: int = _MAX_OUTPUT_BYTES,
    ) -> None:
        """Create a sandbox backend with the given capabilities."""
        if timeout <= 0:
            msg = f"timeout must be positive, got {timeout}"
            raise ValueError(msg)

        self._id = str(uuid4())
        self._working_dir = os.path.realpath(working_dir)
        self._default_timeout = timeout
        self._max_output_bytes = max_output_bytes

        # Track allowed paths for file transfer boundary enforcement.
        # Separate sets for read and write permissions.
        self._readable_paths: list[str] = [self._working_dir]
        self._writable_paths: list[str] = [self._working_dir]

        self._caps = CapabilitySet()

        # System paths required for shell command execution
        sys_paths = list(_SYSTEM_PATHS_COMMON)
        if platform.system() == "Darwin":
            sys_paths.extend(_SYSTEM_PATHS_MACOS)

        for sys_path in sys_paths:
            with contextlib.suppress(FileNotFoundError):
                self._caps.allow_path(sys_path, AccessMode.READ)

        # /dev needs read for /dev/urandom, /dev/tty etc.
        # /dev/null specifically needs write for shell redirects (2>/dev/null).
        with contextlib.suppress(FileNotFoundError):
            self._caps.allow_path("/dev", AccessMode.READ)
        with contextlib.suppress(FileNotFoundError):
            self._caps.allow_file("/dev/null", AccessMode.READ_WRITE)

        # Python interpreter and standard library — required by BaseSandbox
        # which shells out to `python3 -c "..."` for ls, glob, read, write, edit.
        # In venv environments sys.prefix (venv root) and sys.base_prefix
        # (real Python installation) differ. Both are needed: the venv
        # has bin/python3 (often a symlink) and site-packages, while
        # base_prefix has the actual interpreter binary and stdlib.
        for python_path in {
            os.path.realpath(sys.prefix),
            os.path.realpath(sys.base_prefix),
        }:
            with contextlib.suppress(FileNotFoundError):
                self._caps.allow_path(python_path, AccessMode.READ)

        # Working directory gets read-write
        self._caps.allow_path(working_dir, AccessMode.READ_WRITE)

        for path in allow_read or []:
            self._caps.allow_path(path, AccessMode.READ)
            self._readable_paths.append(os.path.realpath(path))
        for path in allow_write or []:
            self._caps.allow_path(path, AccessMode.WRITE)
            self._writable_paths.append(os.path.realpath(path))
        for path in allow_readwrite or []:
            self._caps.allow_path(path, AccessMode.READ_WRITE)
            real = os.path.realpath(path)
            self._readable_paths.append(real)
            self._writable_paths.append(real)

        if block_network:
            self._caps.block_network()

    def _is_path_readable(self, path: str) -> bool:
        """Check if a path falls within a readable directory."""
        return self._check_path_in_list(path, self._readable_paths)

    def _is_path_writable(self, path: str) -> bool:
        """Check if a path falls within a writable directory."""
        return self._check_path_in_list(path, self._writable_paths)

    @staticmethod
    def _check_path_in_list(path: str, allowed: list[str]) -> bool:
        """Check if path falls within any allowed directory.

        Uses component-based path comparison, not string prefix matching,
        to prevent path traversal attacks (e.g., /tmp-evil matching /tmp).
        """
        real = os.path.realpath(path)
        for allowed_path in allowed:
            try:
                common = os.path.commonpath([real, allowed_path])
                if common == allowed_path:
                    return True
            except ValueError:
                continue
        return False

    @property
    def id(self) -> str:
        """Unique identifier for this sandbox instance."""
        return self._id

    def execute(
        self,
        command: str,
        *,
        timeout: int | None = None,
    ) -> ExecuteResponse:
        """Execute a shell command in a sandboxed child process.

        Args:
            command: Shell command string to execute.
            timeout: Maximum time in seconds to wait for completion.
                If None, uses the backend's default timeout. Must be
                positive if provided.

        Returns:
            ExecuteResponse with combined output, exit code, and
            truncation flag.
        """
        effective_timeout = timeout if timeout is not None else self._default_timeout

        if effective_timeout <= 0:
            msg = f"timeout must be positive, got {effective_timeout}"
            raise ValueError(msg)

        result = sandboxed_exec(
            caps=self._caps,
            command=["bash", "-c", command],
            cwd=self._working_dir,
            timeout_secs=float(effective_timeout),
        )

        output = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace")
        if stderr.strip():
            output += f"\n<stderr>{stderr.strip()}</stderr>"

        truncated = len(output.encode("utf-8")) > self._max_output_bytes
        if truncated:
            output = output[: self._max_output_bytes]

        return ExecuteResponse(
            output=output,
            exit_code=result.exit_code,
            truncated=truncated,
        )

    def upload_files(
        self,
        files: list[tuple[str, bytes]],
    ) -> list[FileUploadResponse]:
        """Write files to the local filesystem within writable paths.

        Only paths within the working directory or paths explicitly
        granted write or read-write access are permitted.

        Args:
            files: List of (absolute_path, content) tuples.

        Returns:
            List of FileUploadResponse with per-file status.
        """
        responses: list[FileUploadResponse] = []
        for path, content in files:
            if not path.startswith("/"):
                responses.append(FileUploadResponse(path=path, error="invalid_path"))
                continue
            if not self._is_path_writable(path):
                responses.append(
                    FileUploadResponse(path=path, error="permission_denied")
                )
                continue
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "wb") as f:
                    f.write(content)
                responses.append(FileUploadResponse(path=path, error=None))
            except OSError:
                responses.append(
                    FileUploadResponse(path=path, error="permission_denied")
                )
        return responses

    def download_files(
        self,
        paths: list[str],
    ) -> list[FileDownloadResponse]:
        """Read files from the local filesystem within readable paths.

        Only paths within the working directory or paths explicitly
        granted read or read-write access are permitted.

        Args:
            paths: List of absolute file paths to download.

        Returns:
            List of FileDownloadResponse with per-file content or error.
        """
        responses: list[FileDownloadResponse] = []
        for path in paths:
            if not path.startswith("/"):
                responses.append(
                    FileDownloadResponse(path=path, content=None, error="invalid_path")
                )
                continue
            if not self._is_path_readable(path):
                responses.append(
                    FileDownloadResponse(
                        path=path, content=None, error="permission_denied"
                    )
                )
                continue
            try:
                if os.path.isdir(path):
                    responses.append(
                        FileDownloadResponse(
                            path=path, content=None, error="is_directory"
                        )
                    )
                    continue
                with open(path, "rb") as f:
                    content = f.read()
                responses.append(
                    FileDownloadResponse(path=path, content=content, error=None)
                )
            except FileNotFoundError:
                responses.append(
                    FileDownloadResponse(
                        path=path, content=None, error="file_not_found"
                    )
                )
            except OSError:
                responses.append(
                    FileDownloadResponse(
                        path=path, content=None, error="permission_denied"
                    )
                )
        return responses
