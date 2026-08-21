"""Behavioural tests for authenticated issuance events."""

from __future__ import annotations

import asyncio
from pathlib import Path

import asyncssh
import pyotp

from ski.journal import Event
from ski.state import StateDatabase
from support import enrolled_runtime, mfa_client_factory


def test_authenticated_completion_event_is_redacted_and_group_aware(
    tmp_path: Path,
) -> None:
    """Completion events carry only request, identity, decision, and groups."""

    async def exercise() -> list[Event]:
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
                assert stderr == ""
            return list(enrolled.event_sink.events)

    events = asyncio.run(exercise())
    completion = next(
        event for event in events if event.name == "certificate_request_completed"
    )
    assert set(completion.fields) == {
        "SKI_REQUEST_ID",
        "SKI_IDENTITY",
        "SKI_DECISION",
        "SKI_GROUPS",
        "SKI_CERTIFICATE_SERIAL",
    }
    assert completion.fields["SKI_IDENTITY"] == "alice"
    assert completion.fields["SKI_DECISION"] == "allow"
    assert completion.fields["SKI_GROUPS"] == "platform-ops"
    assert completion.fields["SKI_REQUEST_ID"]
    rendered = repr(events)
    assert "password" not in rendered
    assert "JBSWY3DPEHPK3PXP" not in rendered


def test_injection_failure_response_and_event_are_redacted(tmp_path: Path) -> None:
    """An unavailable forwarded agent cannot expose credentials or transport data."""

    async def exercise() -> tuple[list[Event], Path]:
        async with enrolled_runtime(tmp_path, username="alice") as enrolled:
            async with asyncssh.connect(
                "127.0.0.1",
                port=enrolled.runtime.issuer.port,
                username="alice",
                known_hosts=None,
                agent_path="/tmp/ski-test-agent-does-not-exist",
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
                assert process.exit_status == 1
                assert stdout == ""
                assert stderr == "Certificate request failed.\n"
            return list(enrolled.event_sink.events), enrolled.database

    events, database_path = asyncio.run(exercise())
    failure = next(
        event for event in events if event.name == "certificate_request_failed"
    )
    assert set(failure.fields) == {
        "SKI_REQUEST_ID",
        "SKI_IDENTITY",
        "SKI_DECISION",
        "SKI_GROUPS",
        "SKI_ERROR_CODE",
    }
    assert failure.fields["SKI_DECISION"] == "deny"
    rendered = repr(events)
    assert "-----BEGIN" not in rendered
    assert "agent" not in rendered.lower()
    database = StateDatabase.open(database_path, owner=True)
    try:
        assert database.list_certificates() == ()
        assert database.list_events()[-1].kind == "certificate_failed"
    finally:
        database.close()
