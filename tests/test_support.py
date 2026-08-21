"""Behavioural tests for shared integration-test support."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from support import mfa_client_factory, ssh_agent


def test_ssh_agent_context_exposes_socket_and_cleans_up() -> None:
    """A real agent is available inside the context and gone afterwards."""

    async def exercise() -> None:
        socket_path: Path
        async with ssh_agent() as environment:
            socket_path = Path(environment["SSH_AUTH_SOCK"])
            assert socket_path.exists()

        assert not socket_path.exists()

    asyncio.run(exercise())


def test_mfa_client_factory_answers_and_records_prompts() -> None:
    """The shared MFA client supplies factors and records challenge labels."""
    client = mfa_client_factory("password", "123456")()

    assert client.kbdint_auth_requested() == ""
    assert client.kbdint_challenge_received(
        "",
        "",
        "",
        [("Password:", True), ("2FA:", False)],
    ) == ["password", "123456"]
    assert client.prompts == ("Password:", "2FA:")


def test_ssh_agent_context_cleans_up_when_scenario_raises() -> None:
    """Agent cleanup runs when the scenario exits with an exception."""

    async def exercise() -> None:
        socket_path: Path
        with pytest.raises(RuntimeError, match="scenario failed"):
            async with ssh_agent() as environment:
                socket_path = Path(environment["SSH_AUTH_SOCK"])
                raise RuntimeError("scenario failed")

        assert not socket_path.exists()

    asyncio.run(exercise())
