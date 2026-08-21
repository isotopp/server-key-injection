"""Behavioural tests for authenticated disposable credential injection."""

from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path

import asyncssh
import pyotp
import pytest

from ski.identities import SqliteIdentityStore
from ski.injection import TracerAgentInjector
from ski.journal import Event, MemoryEventSink
from ski.runtime import ServiceRuntime
from ski.server import TracerIssuer
from ski.state import StateDatabase
from support import MfaClient as _MfaClient
from support import mfa_client_factory, runtime_environment


async def _start_test_agent() -> dict[str, str]:
    process = await asyncio.create_subprocess_exec(
        "ssh-agent",
        "-s",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        raise RuntimeError(stderr.decode())
    output = stdout.decode()
    socket_match = re.search(r"SSH_AUTH_SOCK=([^;]+);", output)
    pid_match = re.search(r"SSH_AGENT_PID=([^;]+);", output)
    if socket_match is None or pid_match is None:
        raise RuntimeError("ssh-agent did not report its environment")
    return {
        "SSH_AUTH_SOCK": socket_match.group(1),
        "SSH_AGENT_PID": pid_match.group(1),
    }


async def _stop_test_agent(environment: dict[str, str]) -> None:
    process = await asyncio.create_subprocess_exec(
        "ssh-agent",
        "-k",
        env={**os.environ, **environment},
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await process.communicate()
    Path(environment["SSH_AUTH_SOCK"]).unlink(missing_ok=True)


def test_authenticated_forwarded_request_injects_dummy_identity_and_groups(
    tmp_path: Path,
) -> None:
    """MFA and forwarding produce one disposable identity and group summary."""
    database = StateDatabase.open(tmp_path / "state.sqlite3")

    async def exercise() -> None:
        agent_environment = await _start_test_agent()
        try:
            store = SqliteIdentityStore(database)
            user = store.create_user("alice", "password", "JBSWY3DPEHPK3PXP")
            store.create_group("platform-ops")
            store.add_membership("platform-ops", "alice")
            issuer = TracerIssuer(
                bind="127.0.0.1",
                port=0,
                identity_store=store,
                request_handler=TracerAgentInjector().handle,
            )
            await issuer.start()
            try:
                async with asyncssh.connect(
                    "127.0.0.1",
                    port=issuer.port,
                    username="alice",
                    known_hosts=None,
                    agent_path=agent_environment["SSH_AUTH_SOCK"],
                    agent_forwarding=True,
                    client_factory=mfa_client_factory(
                        "password", pyotp.TOTP(user.totp_secret).now()
                    ),
                    kbdint_auth=True,
                ) as connection:
                    process = await connection.create_process(
                        command=None,
                        request_pty=False,
                    )
                    stdout, stderr = await process.communicate()
                    assert process.exit_status == 0
                    assert stdout.startswith("Key loaded: test-")
                    assert "Groups: platform-ops" in stdout
                    assert stderr == ""

                listed = await asyncio.create_subprocess_exec(
                    "ssh-add",
                    "-l",
                    env={**os.environ, **agent_environment},
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                listing, errors = await listed.communicate()
                assert listed.returncode == 0, errors.decode()
                assert b"test-" in listing
            finally:
                await issuer.close()
        finally:
            await _stop_test_agent(agent_environment)

    try:
        asyncio.run(exercise())
    finally:
        database.close()


def test_ordinary_renewal_preserves_an_unrelated_agent_identity(
    tmp_path: Path,
) -> None:
    """Renewal removes only the current user's ski credential."""
    database_path = tmp_path / "state.sqlite3"
    database = StateDatabase.open(database_path)
    try:
        user = SqliteIdentityStore(database).create_user(
            "alice",
            "password",
            "JBSWY3DPEHPK3PXP",
        )
    finally:
        database.close()

    async def exercise() -> bytes:
        agent_environment = await _start_test_agent()
        unrelated_key_path = tmp_path / "unrelated"
        unrelated_key = asyncssh.generate_private_key(
            "ssh-ed25519", comment="unrelated"
        )
        unrelated_key_path.write_bytes(unrelated_key.export_private_key())
        unrelated_key_path.chmod(0o600)
        add_process = await asyncio.create_subprocess_exec(
            "ssh-add",
            str(unrelated_key_path),
            env={**os.environ, **agent_environment},
        )
        await add_process.wait()
        assert add_process.returncode == 0
        try:
            runtime = ServiceRuntime(
                bind="127.0.0.1",
                port=0,
                exported_environment=runtime_environment(tmp_path, database_path),
                event_sink=MemoryEventSink(),
            )
            await runtime.start()
            try:
                for _ in range(2):
                    async with asyncssh.connect(
                        "127.0.0.1",
                        port=runtime.issuer.port,
                        username="alice",
                        known_hosts=None,
                        agent_path=agent_environment["SSH_AUTH_SOCK"],
                        agent_forwarding=True,
                        client_factory=lambda: _MfaClient(
                            "password",
                            pyotp.TOTP(user.totp_secret).now(),
                        ),
                        kbdint_auth=True,
                    ) as connection:
                        process = await connection.create_process(
                            command=None,
                            request_pty=False,
                        )
                        stdout, stderr = await process.communicate()
                        assert process.exit_status == 0, stderr
                listed = await asyncio.create_subprocess_exec(
                    "ssh-add",
                    "-L",
                    env={**os.environ, **agent_environment},
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                listing, errors = await listed.communicate()
                assert listed.returncode == 0, errors.decode()
                return listing
            finally:
                await runtime.close()
        finally:
            await _stop_test_agent(agent_environment)

    listing = asyncio.run(exercise())
    assert b"unrelated" in listing
    assert b"ski:alice:" in listing


def test_authenticated_request_without_forwarding_does_not_inject(
    tmp_path: Path,
) -> None:
    """Successful MFA without forwarding reports failure and leaves the agent empty."""
    database = StateDatabase.open(tmp_path / "state.sqlite3")

    async def exercise() -> None:
        agent_environment = await _start_test_agent()
        try:
            store = SqliteIdentityStore(database)
            user = store.create_user("alice", "password", "JBSWY3DPEHPK3PXP")
            issuer = TracerIssuer(
                bind="127.0.0.1",
                port=0,
                identity_store=store,
                request_handler=TracerAgentInjector().handle,
            )
            await issuer.start()
            try:
                async with asyncssh.connect(
                    "127.0.0.1",
                    port=issuer.port,
                    username="alice",
                    known_hosts=None,
                    agent_forwarding=False,
                    client_factory=lambda: _MfaClient(
                        "password",
                        pyotp.TOTP(user.totp_secret).now(),
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
                    assert stderr == "Agent forwarding is required.\n"

                listed = await asyncio.create_subprocess_exec(
                    "ssh-add",
                    "-l",
                    env={**os.environ, **agent_environment},
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                listing, _ = await listed.communicate()
                assert listed.returncode != 0
                assert b"The agent has no identities" in listing
            finally:
                await issuer.close()
        finally:
            await _stop_test_agent(agent_environment)

    try:
        asyncio.run(exercise())
    finally:
        database.close()


def test_group_snapshot_failure_denies_before_agent_injection(tmp_path: Path) -> None:
    """A group backend failure closes the request without partial output or keys."""
    database = StateDatabase.open(tmp_path / "state.sqlite3")

    async def exercise() -> None:
        agent_environment = await _start_test_agent()
        try:
            store = SqliteIdentityStore(database)
            user = store.create_user("alice", "password", "JBSWY3DPEHPK3PXP")

            class BrokenGroupStore(SqliteIdentityStore):
                def get_group_snapshot(self, username: str):
                    raise RuntimeError("group backend unavailable")

            issuer = TracerIssuer(
                bind="127.0.0.1",
                port=0,
                identity_store=BrokenGroupStore(database),
                request_handler=TracerAgentInjector().handle,
            )
            await issuer.start()
            try:
                with pytest.raises(
                    (asyncssh.PermissionDenied, asyncssh.ConnectionLost)
                ):
                    async with asyncssh.connect(
                        "127.0.0.1",
                        port=issuer.port,
                        username="alice",
                        known_hosts=None,
                        agent_path=agent_environment["SSH_AUTH_SOCK"],
                        agent_forwarding=True,
                        client_factory=lambda: _MfaClient(
                            "password",
                            pyotp.TOTP(user.totp_secret).now(),
                        ),
                        kbdint_auth=True,
                    ):
                        pass

                listed = await asyncio.create_subprocess_exec(
                    "ssh-add",
                    "-l",
                    env={**os.environ, **agent_environment},
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                listing, _ = await listed.communicate()
                assert listed.returncode != 0
                assert b"The agent has no identities" in listing
            finally:
                await issuer.close()
        finally:
            await _stop_test_agent(agent_environment)

    try:
        asyncio.run(exercise())
    finally:
        database.close()


def test_runtime_restart_keeps_host_key_but_rotates_ordinary_user_credentials(
    tmp_path: Path,
) -> None:
    """A database keeps its host key while each runtime gets a fresh user key."""
    database_path = tmp_path / "state.sqlite3"
    database = StateDatabase.open(database_path)
    try:
        SqliteIdentityStore(database).create_user(
            "alice",
            "password",
            "JBSWY3DPEHPK3PXP",
        )
    finally:
        database.close()

    async def exercise() -> tuple[str, set[bytes], str, set[bytes]]:
        agent_environment = await _start_test_agent()
        try:
            observations: list[tuple[str, set[bytes]]] = []
            for _ in range(2):
                runtime = ServiceRuntime(
                    bind="127.0.0.1",
                    port=0,
                    exported_environment=runtime_environment(tmp_path, database_path),
                    event_sink=MemoryEventSink(),
                )
                await runtime.start()
                try:
                    async with asyncssh.connect(
                        "127.0.0.1",
                        port=runtime.issuer.port,
                        username="alice",
                        known_hosts=None,
                        agent_path=agent_environment["SSH_AUTH_SOCK"],
                        agent_forwarding=True,
                        client_factory=lambda: _MfaClient(
                            "password",
                            pyotp.TOTP("JBSWY3DPEHPK3PXP").now(),
                        ),
                        kbdint_auth=True,
                    ) as connection:
                        process = await connection.create_process(
                            command=None,
                            request_pty=False,
                        )
                        stdout, stderr = await process.communicate()
                        assert process.exit_status == 0, stderr
                        assert stdout.startswith("Key loaded: alice ")
                        assert stderr == ""
                        host_key = connection.get_server_host_key()
                        assert host_key is not None
                        fingerprint = host_key.get_fingerprint()

                    listed = await asyncio.create_subprocess_exec(
                        "ssh-add",
                        "-L",
                        env={**os.environ, **agent_environment},
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    listing, errors = await listed.communicate()
                    assert listed.returncode == 0, errors.decode()
                    observations.append(
                        (
                            fingerprint,
                            {
                                line
                                for line in listing.splitlines()
                                if b"ski:alice:" in line
                            },
                        ),
                    )
                finally:
                    await runtime.close()
            return (
                observations[0][0],
                observations[0][1],
                observations[1][0],
                observations[1][1],
            )
        finally:
            await _stop_test_agent(agent_environment)

    try:
        first_host, first_keys, second_host, second_keys = asyncio.run(exercise())
        assert first_host == second_host
        assert first_keys
        assert second_keys
        assert second_keys != first_keys
    finally:
        database.close()


def test_authenticated_completion_event_is_redacted_and_group_aware(
    tmp_path: Path,
) -> None:
    """Completion events carry only request, identity, decision, and groups."""
    database_path = tmp_path / "state.sqlite3"
    database = StateDatabase.open(database_path)
    try:
        store = SqliteIdentityStore(database)
        user = store.create_user("alice", "password", "JBSWY3DPEHPK3PXP")
        store.create_group("platform-ops")
        store.add_membership("platform-ops", "alice")
    finally:
        database.close()

    async def exercise() -> list[Event]:
        agent_environment = await _start_test_agent()
        sink = MemoryEventSink()
        runtime = ServiceRuntime(
            bind="127.0.0.1",
            port=0,
            exported_environment=runtime_environment(tmp_path, database_path),
            event_sink=sink,
        )
        await runtime.start()
        try:
            async with asyncssh.connect(
                "127.0.0.1",
                port=runtime.issuer.port,
                username="alice",
                known_hosts=None,
                agent_path=agent_environment["SSH_AUTH_SOCK"],
                agent_forwarding=True,
                client_factory=lambda: _MfaClient(
                    "password",
                    pyotp.TOTP(user.totp_secret).now(),
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
        finally:
            await runtime.close()
            await _stop_test_agent(agent_environment)
        return list(sink.events)

    try:
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
    finally:
        database.close()


def test_injection_failure_response_and_event_are_redacted(tmp_path: Path) -> None:
    """An unavailable forwarded agent cannot expose credentials or transport data."""
    database_path = tmp_path / "state.sqlite3"
    database = StateDatabase.open(database_path)
    try:
        user = SqliteIdentityStore(database).create_user(
            "alice",
            "password",
            "JBSWY3DPEHPK3PXP",
        )
    finally:
        database.close()

    async def exercise() -> list[Event]:
        sink = MemoryEventSink()
        runtime = ServiceRuntime(
            bind="127.0.0.1",
            port=0,
            exported_environment=runtime_environment(tmp_path, database_path),
            event_sink=sink,
        )
        await runtime.start()
        try:
            async with asyncssh.connect(
                "127.0.0.1",
                port=runtime.issuer.port,
                username="alice",
                known_hosts=None,
                agent_path="/tmp/ski-test-agent-does-not-exist",
                agent_forwarding=True,
                client_factory=lambda: _MfaClient(
                    "password",
                    pyotp.TOTP(user.totp_secret).now(),
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
        finally:
            await runtime.close()
        return list(sink.events)

    try:
        events = asyncio.run(exercise())
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
    finally:
        database.close()
