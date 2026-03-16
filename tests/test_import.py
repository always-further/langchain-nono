"""Test that the package can be imported."""

from __future__ import annotations

import langchain_nono


def test_import_nono() -> None:
    """Verify the package imports successfully."""
    assert langchain_nono is not None


def test_import_sandbox_class() -> None:
    """Verify NonoSandbox is importable from the package."""
    from langchain_nono import NonoSandbox

    assert NonoSandbox is not None
