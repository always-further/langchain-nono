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
from nono_py import (
    AccessMode,
    CapabilitySet,
    ExclusionConfig,
    ProxyConfig,
    SessionMetadata,
    SnapshotManager,
    apply_unlink_overrides,
    load_policy,
    sandboxed_exec,
    start_proxy,
    validate_deny_overlaps,
)

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
        policy_json: Raw nono policy JSON to resolve into capabilities.
        policy_groups: Policy group names to resolve from policy_json.
        proxy_config: Optional network filtering proxy configuration.
        snapshot_session_dir: Optional session directory for snapshots.
        snapshot_tracked_paths: Optional tracked roots for snapshots.
        snapshot_exclusion: Optional snapshot exclusion configuration.
        snapshot_max_entries: Maximum tracked snapshot entries.
        snapshot_max_bytes: Maximum tracked snapshot bytes.
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
        policy_json: str | None = None,
        policy_groups: list[str] | None = None,
        proxy_config: ProxyConfig | None = None,
        snapshot_session_dir: str | None = None,
        snapshot_tracked_paths: list[str] | None = None,
        snapshot_exclusion: ExclusionConfig | None = None,
        snapshot_max_entries: int = 300_000,
        snapshot_max_bytes: int = 2_147_483_648,
        block_network: bool = True,
        timeout: int = 30 * 60,
        max_output_bytes: int = _MAX_OUTPUT_BYTES,
    ) -> None:
        """Create a sandbox backend with the given capabilities."""
        if timeout <= 0:
            msg = f"timeout must be positive, got {timeout}"
            raise ValueError(msg)
        if policy_json is None and policy_groups:
            msg = "policy_groups requires policy_json"
            raise ValueError(msg)
        if policy_json is not None and not policy_groups:
            msg = "policy_json requires at least one policy group"
            raise ValueError(msg)
        if proxy_config is not None and not block_network:
            msg = "proxy_config requires block_network=True"
            raise ValueError(msg)

        self._id = str(uuid4())
        self._working_dir = os.path.realpath(working_dir)
        self._default_timeout = timeout
        self._max_output_bytes = max_output_bytes
        self._proxy_handle = None
        self._proxy_env: list[tuple[str, str]] | None = None
        self._snapshot_manager = None

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

        if policy_json is not None:
            resolved = load_policy(policy_json).resolve_groups(
                policy_groups, self._caps
            )
            if resolved.needs_unlink_overrides:
                apply_unlink_overrides(self._caps)
            validate_deny_overlaps(resolved.deny_paths, self._caps)

            for capability in self._caps.fs_capabilities():
                if not str(capability.source).startswith("group"):
                    continue
                self._register_transfer_path(capability.resolved, capability.access)

        if block_network:
            self._caps.block_network()

        if proxy_config is not None:
            self._proxy_handle = start_proxy(proxy_config)
            self._proxy_env = list(self._proxy_handle.env_vars().items()) + list(
                self._proxy_handle.credential_env_vars().items()
            )

        if snapshot_session_dir is not None:
            tracked_paths = snapshot_tracked_paths or [self._working_dir]
            self._snapshot_manager = SnapshotManager(
                session_dir=snapshot_session_dir,
                tracked_paths=tracked_paths,
                exclusion=snapshot_exclusion,
                max_entries=snapshot_max_entries,
                max_bytes=snapshot_max_bytes,
            )

    def _register_transfer_path(self, path: str, access: AccessMode) -> None:
        """Track allowed paths for upload/download policy enforcement."""
        real = os.path.realpath(path)
        if access in {AccessMode.READ, AccessMode.READ_WRITE}:
            if real not in self._readable_paths:
                self._readable_paths.append(real)
        if access in {AccessMode.WRITE, AccessMode.READ_WRITE}:
            if real not in self._writable_paths:
                self._writable_paths.append(real)

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
            command=["/bin/bash", "-c", command],
            cwd=self._working_dir,
            timeout_secs=float(effective_timeout),
            env=self._proxy_env,
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

    def drain_network_audit_events(self) -> list[dict[str, object]]:
        """Drain audit events from the configured proxy."""
        if self._proxy_handle is None:
            return []
        return self._proxy_handle.drain_audit_events()

    def shutdown_proxy(self) -> None:
        """Shut down the configured proxy if one is running."""
        if self._proxy_handle is None:
            return
        self._proxy_handle.shutdown()
        self._proxy_handle = None
        self._proxy_env = None

    def create_snapshot_baseline(self):
        """Create a baseline snapshot for the configured session."""
        if self._snapshot_manager is None:
            msg = "snapshot support is not configured"
            raise RuntimeError(msg)
        return self._snapshot_manager.create_baseline()

    def create_snapshot_incremental(self):
        """Create an incremental snapshot for the configured session."""
        if self._snapshot_manager is None:
            msg = "snapshot support is not configured"
            raise RuntimeError(msg)
        return self._snapshot_manager.create_incremental()

    def restore_snapshot(self, snapshot_number: int):
        """Restore tracked files to a previous snapshot."""
        if self._snapshot_manager is None:
            msg = "snapshot support is not configured"
            raise RuntimeError(msg)
        return self._snapshot_manager.restore_to(snapshot_number)

    def compute_restore_diff(self, snapshot_number: int):
        """Dry-run showing what changes a restore would apply."""
        if self._snapshot_manager is None:
            msg = "snapshot support is not configured"
            raise RuntimeError(msg)
        return self._snapshot_manager.compute_restore_diff(snapshot_number)

    def load_snapshot_manifest(self, snapshot_number: int):
        """Load a snapshot manifest by number."""
        if self._snapshot_manager is None:
            msg = "snapshot support is not configured"
            raise RuntimeError(msg)
        return self._snapshot_manager.load_manifest(snapshot_number)

    def save_session_metadata(self, meta: SessionMetadata) -> None:
        """Save session metadata to the snapshot session directory."""
        if self._snapshot_manager is None:
            msg = "snapshot support is not configured"
            raise RuntimeError(msg)
        self._snapshot_manager.save_session_metadata(meta)

    @staticmethod
    def load_session_metadata(session_dir: str):
        """Load session metadata from a session directory."""
        return SnapshotManager.load_session_metadata(session_dir)

    def snapshot_count(self) -> int:
        """Return the number of snapshots recorded for this sandbox."""
        if self._snapshot_manager is None:
            return 0
        return self._snapshot_manager.snapshot_count()

    @staticmethod
    def resolve_proxy_from_policy(
        policy_json: str, groups: list[str]
    ) -> ProxyConfig | None:
        """Resolve a ProxyConfig from policy JSON network groups.

        Returns None when the requested groups do not define proxy rules.
        """
        return load_policy(policy_json).resolve_proxy_config(groups)

    def __del__(self) -> None:
        """Best-effort cleanup for background proxy resources."""
        with contextlib.suppress(Exception):
            self.shutdown_proxy()

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
