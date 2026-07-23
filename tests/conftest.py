"""Shared test configuration.

The one global guarantee enforced here: **the test suite never touches the
network.** DepTrace's LLM and vulnerability layers both talk to remote APIs
in production, and both are supposed to be fully substitutable in tests
(`TestModel`/`FunctionModel`, `httpx.MockTransport`). A test that silently
reaches the real internet would be slow, flaky, key-dependent, and would
quietly break the "runs offline in CI" property this project advertises.

Rather than trust that, we make it impossible: any attempt to open a socket
fails the test with the address it tried to reach.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from typing import Any

import pytest

_real_connect = socket.socket.connect


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Block outbound sockets for the duration of every test."""

    def blocked(self: socket.socket, address: Any, *args: Any, **kwargs: Any) -> None:
        raise AssertionError(
            f"Test attempted a real network call to {address!r}. "
            "Use TestModel/FunctionModel or httpx.MockTransport instead."
        )

    monkeypatch.setattr(socket.socket, "connect", blocked)
    yield


@pytest.fixture(autouse=True)
def clean_llm_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Neutralize ambient LLM configuration.

    Provider selection reads the environment, so a developer with
    GROQ_API_KEY exported would otherwise get different test results than
    CI — the classic "passes on my machine" failure.
    """
    for var in (
        "DEPTRACE_LLM_PROVIDER",
        "DEPTRACE_LLM_MODEL",
        "DEPTRACE_LLM_BASE_URL",
        "DEPTRACE_LLM_CONCURRENCY",
        "GROQ_API_KEY",
        "GEMINI_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)
    yield
