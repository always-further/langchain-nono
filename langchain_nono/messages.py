"""Helpers for translating sandbox failures into user-facing messages."""

from __future__ import annotations


def describe_execute_failure(exit_code: int, output: str) -> str | None:
    """Return a clearer message for a failed sandboxed command."""
    if exit_code == 0:
        return None

    cleaned = output.strip()
    if "Operation not permitted" in cleaned:
        return "access denied by sandbox policy"
    if exit_code == 124:
        return "command timed out"
    if "<stderr>" in cleaned:
        return "command failed inside sandbox"
    return f"command failed with exit code {exit_code}"


def describe_file_transfer_error(error: str | None) -> str:
    """Translate a file-transfer error code into a user-facing message."""
    if error is None:
        return "ok"
    if error == "permission_denied":
        return "access denied by sandbox policy"
    if error == "file_not_found":
        return "path is allowed, but the file does not exist"
    if error == "is_directory":
        return "expected a file but got a directory"
    if error == "invalid_path":
        return "expected an absolute path"
    return error
