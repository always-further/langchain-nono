"""Tests for user-facing sandbox error messages."""

from __future__ import annotations

from langchain_nono import (
    describe_execute_failure,
    describe_file_transfer_error,
)


def test_describe_execute_failure_success_returns_none() -> None:
    """Successful commands should not produce an error message."""
    assert describe_execute_failure(0, "ok") is None


def test_describe_execute_failure_policy_denial() -> None:
    """Sandbox permission failures should get a clearer message."""
    message = describe_execute_failure(
        1,
        "<stderr>cat: secret.txt: Operation not permitted</stderr>",
    )
    assert message == "access denied by sandbox policy"


def test_describe_execute_failure_timeout() -> None:
    """Timeouts should be translated explicitly."""
    assert describe_execute_failure(124, "") == "command timed out"


def test_describe_file_transfer_error_permission_denied() -> None:
    """Transfer permission errors should get a clearer message."""
    assert (
        describe_file_transfer_error("permission_denied")
        == "access denied by sandbox policy"
    )


def test_describe_file_transfer_error_none() -> None:
    """Successful transfers should report ok."""
    assert describe_file_transfer_error(None) == "ok"
