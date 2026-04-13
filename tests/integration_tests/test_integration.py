"""Standard LangChain integration tests for NonoSandbox."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from langchain_tests.integration_tests import (
    SandboxIntegrationTests,
)

from langchain_nono import NonoSandbox

if TYPE_CHECKING:
    from collections.abc import Iterator

    from deepagents.backends.protocol import (
        SandboxBackendProtocol,
    )


class TestNonoSandboxStandard(SandboxIntegrationTests):
    """Run the standard LangChain sandbox test suite against NonoSandbox."""

    @pytest.fixture(scope="class")
    def sandbox(self) -> Iterator[SandboxBackendProtocol]:
        """Yield a NonoSandbox with /tmp read-write access.

        The standard test suite writes to /tmp/test_sandbox_ops and other
        /tmp paths, so the sandbox must grant read-write access to /tmp.
        """
        backend = NonoSandbox(
            working_dir="/tmp",
            block_network=True,
        )
        yield backend
