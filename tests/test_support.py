"""Behavioural tests for shared integration-test support."""

from __future__ import annotations

import asyncio
from pathlib import Path

import asyncssh
import pyotp
import pytest

from ski.state import StateDatabase
from support import enrolled_runtime, mfa_client_factory, ssh_agent


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


def test_enrolled_runtime_owns_issuer_identity_and_agent(tmp_path: Path) -> None:
    """An enrolled runtime exposes configured user/group state and an agent."""

    async def exercise() -> None:
        async with enrolled_runtime(
            tmp_path,
            username="alice",
            groups=("platform-ops",),
        ) as enrolled:
            socket_path = Path(enrolled.agent_environment["SSH_AUTH_SOCK"])
            assert enrolled.user.username == "alice"
            assert enrolled.user.groups == ("platform-ops",)
            assert enrolled.runtime.issuer.port > 0
            assert socket_path.exists()

        assert not socket_path.exists()

    asyncio.run(exercise())


def test_enrolled_runtime_supports_authenticated_issuance(tmp_path: Path) -> None:
    """A fixture-backed real SSH exchange retains ordinary issuance output."""

    async def exercise() -> None:
        async with enrolled_runtime(
            tmp_path,
            username="alice",
            groups=("platform-ops",),
        ) as enrolled:
            async with asyncssh.connect(
                "127.0.0.1",
                port=enrolled.runtime.issuer.port,
                username="alice",
                known_hosts=None,
                agent_path=enrolled.agent_environment["SSH_AUTH_SOCK"],
                agent_forwarding=True,
                client_factory=mfa_client_factory(
                    "password", pyotp.TOTP(enrolled.user.totp_secret).now()
                ),
                kbdint_auth=True,
            ) as connection:
                process = await connection.create_process(
                    command=None,
                    request_pty=False,
                )
                stdout, stderr = await process.communicate()

                assert process.exit_status == 0
                assert stdout.startswith("Key loaded: alice ")
                assert "Groups: platform-ops" in stdout
                assert stderr == ""

    asyncio.run(exercise())


def test_enrolled_runtime_releases_resources_for_followup_use(tmp_path: Path) -> None:
    """Closing the fixture releases the runtime listener and database lock."""

    async def exercise() -> None:
        runtime = None
        async with enrolled_runtime(tmp_path) as enrolled:
            runtime = enrolled.runtime

        assert runtime is not None
        with pytest.raises(RuntimeError, match="not started"):
            runtime.issuer
        state = StateDatabase.open(tmp_path / "state.sqlite3", owner=True)
        state.close()

    asyncio.run(exercise())
