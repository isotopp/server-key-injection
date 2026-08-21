"""Behavioural tests for the ordered service runtime."""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Sequence
from pathlib import Path
from typing import cast

import asyncssh
import pyotp
import pytest

from ski.configuration import ConfigurationError
from ski.identities import SqliteIdentityStore
from ski.journal import MemoryEventSink
from ski.runtime import IssuerFactory, ServiceRuntime, StateOpener
from ski.state import StateDatabase, StateError
from support import runtime_environment


class _RuntimeMfaClient(asyncssh.SSHClient):
    def __init__(self, password: str, code: str) -> None:
        self.password = password
        self.code = code

    def kbdint_auth_requested(self) -> str:
        return ""

    def kbdint_challenge_received(
        self,
        name: str,
        instructions: str,
        lang: str,
        prompts: Sequence[tuple[str, bool]],
    ) -> list[str]:
        return [self.password, self.code]


def test_service_runtime_rejects_missing_ordinary_ca_before_ready(
    tmp_path: Path,
) -> None:
    """The foreground service fails closed before opening a listener."""

    async def exercise() -> None:
        sink = MemoryEventSink()
        runtime = ServiceRuntime(
            bind="127.0.0.1",
            port=0,
            exported_environment={"SKI_CA_DATABASE": str(tmp_path / "state.sqlite3")},
            event_sink=sink,
        )
        with pytest.raises(ConfigurationError, match="SKI_CA_PRIVATE_KEY"):
            await runtime.start()
        assert sink.events[-1].name == "service_start_failed"
        with pytest.raises(RuntimeError, match="not started"):
            runtime.issuer

    asyncio.run(exercise())


def test_service_runtime_exposes_the_validated_persistent_ca_before_ready(
    tmp_path: Path,
) -> None:
    """A configured listener starts only with the persisted CA material."""
    environment = runtime_environment(tmp_path, tmp_path / "state.sqlite3")

    async def exercise() -> None:
        runtime = ServiceRuntime(
            bind="127.0.0.1",
            port=0,
            exported_environment=environment,
            event_sink=MemoryEventSink(),
        )
        await runtime.start()
        try:
            assert runtime.active_ca.record.fingerprint.startswith("SHA256:")
            assert runtime.active_ca.private_key.get_algorithm() == "ssh-ed25519"
        finally:
            await runtime.close()

    asyncio.run(exercise())


@pytest.mark.parametrize("broken", ["private", "public"])
def test_service_runtime_rejects_missing_active_ca_material_before_ready(
    tmp_path: Path,
    broken: str,
) -> None:
    """A missing configured CA file prevents listener readiness."""
    environment = runtime_environment(tmp_path, tmp_path / "state.sqlite3")
    (tmp_path / ("user_ca" if broken == "private" else "user_ca.pub")).unlink()

    async def exercise() -> None:
        sink = MemoryEventSink()
        runtime = ServiceRuntime(
            bind="127.0.0.1",
            port=0,
            exported_environment=environment,
            event_sink=sink,
        )
        with pytest.raises(StateError, match="active CA"):
            await runtime.start()
        assert sink.events[-1].name == "service_start_failed"
        with pytest.raises(RuntimeError, match="not started"):
            runtime.issuer

    asyncio.run(exercise())


def test_service_runtime_rejects_mismatched_active_ca_material(
    tmp_path: Path,
) -> None:
    """A public/private mismatch never reaches listener startup."""
    environment = runtime_environment(tmp_path, tmp_path / "state.sqlite3")
    other_key = asyncssh.generate_private_key("ssh-ed25519")
    (tmp_path / "user_ca.pub").write_bytes(other_key.export_public_key())

    async def exercise() -> None:
        runtime = ServiceRuntime(
            bind="127.0.0.1",
            port=0,
            exported_environment=environment,
            event_sink=MemoryEventSink(),
        )
        with pytest.raises(StateError, match="does not match"):
            await runtime.start()
        with pytest.raises(RuntimeError, match="not started"):
            runtime.issuer

    asyncio.run(exercise())


def test_service_runtime_starts_state_and_listener_before_ready_event(
    tmp_path: Path,
) -> None:
    """A ready event follows complete state and listener initialization."""

    async def exercise() -> None:
        sink = MemoryEventSink()
        runtime = ServiceRuntime(
            bind="127.0.0.1",
            port=0,
            exported_environment=runtime_environment(
                tmp_path,
                tmp_path / "state.sqlite3",
            ),
            event_sink=sink,
        )
        await runtime.start()
        try:
            assert runtime.state.schema_version == 4
            assert runtime.issuer.port > 0
            ready = sink.events[-1]
            assert ready.name == "service_ready"
            assert ready.fields["SKI_PORT"] == str(runtime.issuer.port)
        finally:
            await runtime.close()

    asyncio.run(exercise())


def test_runtime_reuses_the_database_host_key_after_restart(tmp_path: Path) -> None:
    """The real SSH listener presents the database-owned host key."""
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

    async def fingerprint() -> str:
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
                client_factory=lambda: _RuntimeMfaClient(
                    "password",
                    pyotp.TOTP("JBSWY3DPEHPK3PXP").now(),
                ),
                kbdint_auth=True,
            ) as connection:
                server_host_key = connection.get_server_host_key()
                assert server_host_key is not None
                return server_host_key.get_fingerprint()
        finally:
            await runtime.close()

    async def exercise() -> None:
        assert await fingerprint() == await fingerprint()

    asyncio.run(exercise())


def test_runtime_rejects_corrupt_host_identity_before_listener_start(
    tmp_path: Path,
) -> None:
    """A corrupt persisted host key prevents listening and releases ownership."""
    database_path = tmp_path / "state.sqlite3"
    database = StateDatabase.open(database_path, owner=True)
    try:
        _ = database.host_key
    finally:
        database.close()

    connection = sqlite3.connect(database_path)
    connection.execute(
        "UPDATE ssh_host_keys SET private_key = ? WHERE singleton = 1",
        (b"not-a-private-key",),
    )
    connection.commit()
    connection.close()

    async def exercise() -> None:
        sink = MemoryEventSink()
        runtime = ServiceRuntime(
            bind="127.0.0.1",
            port=0,
            exported_environment=runtime_environment(tmp_path, database_path),
            event_sink=sink,
        )
        with pytest.raises(StateError, match="host key is invalid"):
            await runtime.start()
        with pytest.raises(RuntimeError, match="not started"):
            runtime.issuer
        assert sink.events[-1].name == "service_start_failed"

        reopened = StateDatabase.open(database_path, owner=True)
        reopened.close()

    asyncio.run(exercise())


def test_runtime_reload_swaps_a_valid_configuration_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A valid reload advances the generation without moving the listener."""
    runtime_environment(tmp_path, tmp_path / "state.sqlite3")
    (tmp_path / ".env").write_text(
        f"SKI_CA_DATABASE={tmp_path / 'state.sqlite3'}\n"
        f"SKI_CA_PRIVATE_KEY={tmp_path / 'user_ca'}\n"
        f"SKI_CA_PUBLIC_KEY={tmp_path / 'user_ca.pub'}\n"
        f"SKI_CA_KRL={tmp_path / 'revoked.krl'}\n"
        "ORDINARY_CERT_EXTENSIONS=pty\nSKI_CONFIG_MARKER=one\n",
    )
    monkeypatch.chdir(tmp_path)

    async def exercise() -> None:
        sink = MemoryEventSink()
        runtime = ServiceRuntime(
            bind="127.0.0.1",
            port=0,
            exported_environment={"HOME": str(tmp_path)},
            event_sink=sink,
        )
        await runtime.start()
        try:
            assert runtime.configuration.values["SKI_CONFIG_MARKER"] == "one"
            first_port = runtime.issuer.port
            (tmp_path / ".env").write_text(
                f"SKI_CA_DATABASE={tmp_path / 'state.sqlite3'}\n"
                f"SKI_CA_PRIVATE_KEY={tmp_path / 'user_ca'}\n"
                f"SKI_CA_PUBLIC_KEY={tmp_path / 'user_ca.pub'}\n"
                f"SKI_CA_KRL={tmp_path / 'revoked.krl'}\n"
                "ORDINARY_CERT_EXTENSIONS=pty\n"
                "SKI_CONFIG_MARKER=two\n",
            )

            assert await runtime.reload()
            assert runtime.configuration.values["SKI_CONFIG_MARKER"] == "two"
            assert runtime.configuration_generation == 2
            assert runtime.issuer.port == first_port
            assert sink.events[-1].name == "service_reload_accepted"
        finally:
            await runtime.close()

    asyncio.run(exercise())


def test_runtime_reload_rejects_startup_only_changes_and_invalid_candidates(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Rejected reloads leave the complete previous snapshot active."""
    database_path = tmp_path / "state.sqlite3"
    runtime_environment(tmp_path, database_path)
    (tmp_path / ".env").write_text(
        f"SKI_CA_DATABASE={database_path}\n"
        f"SKI_CA_PRIVATE_KEY={tmp_path / 'user_ca'}\n"
        f"SKI_CA_PUBLIC_KEY={tmp_path / 'user_ca.pub'}\n"
        f"SKI_CA_KRL={tmp_path / 'revoked.krl'}\n"
        "ORDINARY_CERT_EXTENSIONS=pty\nSKI_CONFIG_MARKER=one\n",
    )
    monkeypatch.chdir(tmp_path)

    async def exercise() -> None:
        sink = MemoryEventSink()
        runtime = ServiceRuntime(
            bind="127.0.0.1",
            port=0,
            exported_environment={"HOME": str(tmp_path)},
            event_sink=sink,
        )
        await runtime.start()
        try:
            (tmp_path / ".env").write_text(
                f"SKI_CA_DATABASE={tmp_path / 'other.sqlite3'}\n"
                f"SKI_CA_PRIVATE_KEY={tmp_path / 'user_ca'}\n"
                f"SKI_CA_PUBLIC_KEY={tmp_path / 'user_ca.pub'}\n"
                f"SKI_CA_KRL={tmp_path / 'revoked.krl'}\n"
                "ORDINARY_CERT_EXTENSIONS=pty\n"
                "SKI_CONFIG_MARKER=two\n",
            )
            assert not await runtime.reload()
            assert runtime.configuration.values["SKI_CONFIG_MARKER"] == "one"
            assert sink.events[-1].fields["SKI_ERROR_CODE"] == "restart_required"

            (tmp_path / ".env").write_text("SKI_CONFIG_MARKER=three\n")
            assert not await runtime.reload()
            assert runtime.configuration.values["SKI_CONFIG_MARKER"] == "one"
            assert sink.events[-1].name == "service_reload_rejected"
        finally:
            await runtime.close()

    asyncio.run(exercise())


def test_requests_keep_the_snapshot_with_which_they_started(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Requests retain their original snapshot across an accepted reload."""
    database_path = tmp_path / "state.sqlite3"
    runtime_environment(tmp_path, database_path)
    (tmp_path / ".env").write_text(
        f"SKI_CA_DATABASE={database_path}\n"
        f"SKI_CA_PRIVATE_KEY={tmp_path / 'user_ca'}\n"
        f"SKI_CA_PUBLIC_KEY={tmp_path / 'user_ca.pub'}\n"
        f"SKI_CA_KRL={tmp_path / 'revoked.krl'}\n"
        "ORDINARY_CERT_EXTENSIONS=pty\nSKI_CONFIG_MARKER=one\n",
    )
    monkeypatch.chdir(tmp_path)

    async def exercise() -> None:
        runtime = ServiceRuntime(
            bind="127.0.0.1",
            port=0,
            exported_environment={"HOME": str(tmp_path)},
            event_sink=MemoryEventSink(),
        )
        await runtime.start()
        try:
            async with runtime.request_scope() as request_configuration:
                (tmp_path / ".env").write_text(
                    f"SKI_CA_DATABASE={database_path}\n"
                    f"SKI_CA_PRIVATE_KEY={tmp_path / 'user_ca'}\n"
                    f"SKI_CA_PUBLIC_KEY={tmp_path / 'user_ca.pub'}\n"
                    f"SKI_CA_KRL={tmp_path / 'revoked.krl'}\n"
                    "ORDINARY_CERT_EXTENSIONS=pty\nSKI_CONFIG_MARKER=two\n",
                )
                assert await runtime.reload()
                assert request_configuration.values["SKI_CONFIG_MARKER"] == "one"

            async with runtime.request_scope() as request_configuration:
                assert request_configuration.values["SKI_CONFIG_MARKER"] == "two"
        finally:
            await runtime.close()

    asyncio.run(exercise())


def test_service_runtime_reports_state_failure_without_starting_listener(
    tmp_path: Path,
) -> None:
    """A state failure is redacted and leaves no issuer active."""

    async def exercise() -> None:
        sink = MemoryEventSink()

        def fail_open(*_: object, **__: object) -> None:
            raise RuntimeError("database secret should not be logged")

        runtime = ServiceRuntime(
            bind="127.0.0.1",
            port=0,
            exported_environment=runtime_environment(
                tmp_path,
                tmp_path / "state.sqlite3",
            ),
            event_sink=sink,
            state_opener=cast(StateOpener, fail_open),
        )
        with pytest.raises(RuntimeError):
            await runtime.start()

        with pytest.raises(RuntimeError, match="not started"):
            runtime.issuer
        assert sink.events[-1].name == "service_start_failed"
        assert "database secret" not in sink.events[-1].message

    asyncio.run(exercise())


def test_service_runtime_close_releases_state_and_is_idempotent(tmp_path: Path) -> None:
    """Closing the runtime releases every resource exactly once."""

    async def exercise() -> None:
        database_path = tmp_path / "state.sqlite3"
        sink = MemoryEventSink()
        runtime = ServiceRuntime(
            bind="127.0.0.1",
            port=0,
            exported_environment=runtime_environment(tmp_path, database_path),
            event_sink=sink,
        )
        await runtime.start()
        await runtime.close()
        await runtime.close()

        assert [event.name for event in sink.events] == [
            "service_starting",
            "service_ready",
            "service_stopping",
            "service_stopped",
        ]
        reopened = StateDatabase.open(database_path, owner=True)
        reopened.close()

    asyncio.run(exercise())


def test_listener_start_failure_releases_state_ownership(tmp_path: Path) -> None:
    """A listener failure unwinds the state acquired before it."""

    class FailingIssuer:
        port = 0
        addresses: list[tuple[str, int]] = []

        async def start(self) -> None:
            raise OSError("listener unavailable")

        async def close(self) -> None:
            return

    async def exercise() -> None:
        database_path = tmp_path / "state.sqlite3"
        sink = MemoryEventSink()
        runtime = ServiceRuntime(
            bind="127.0.0.1",
            port=2222,
            exported_environment=runtime_environment(tmp_path, database_path),
            event_sink=sink,
            issuer_factory=cast(IssuerFactory, lambda **_: FailingIssuer()),
        )
        with pytest.raises(OSError, match="listener unavailable"):
            await runtime.start()

        reopened = StateDatabase.open(database_path, owner=True)
        reopened.close()
        assert sink.events[-1].name == "service_start_failed"

    asyncio.run(exercise())


def test_shutdown_drains_an_in_flight_request_before_releasing_state(
    tmp_path: Path,
) -> None:
    """Graceful close waits for bounded request completion after admission stops."""

    async def exercise() -> None:
        runtime = ServiceRuntime(
            bind="127.0.0.1",
            port=0,
            exported_environment=runtime_environment(
                tmp_path,
                tmp_path / "state.sqlite3",
            ),
            event_sink=MemoryEventSink(),
        )
        await runtime.start()
        started = asyncio.Event()
        release = asyncio.Event()

        async def request() -> None:
            async with runtime.request_scope():
                started.set()
                await release.wait()

        request_task = asyncio.create_task(request())
        await started.wait()
        close_task = asyncio.create_task(runtime.close(grace_period=1.0))
        await asyncio.sleep(0)
        assert not close_task.done()

        release.set()
        await request_task
        await close_task

    asyncio.run(exercise())


def test_shutdown_cancels_requests_beyond_the_grace_period(tmp_path: Path) -> None:
    """A request beyond the bound is cancelled before state release."""

    async def exercise() -> None:
        runtime = ServiceRuntime(
            bind="127.0.0.1",
            port=0,
            exported_environment=runtime_environment(
                tmp_path,
                tmp_path / "state.sqlite3",
            ),
            event_sink=MemoryEventSink(),
        )
        await runtime.start()
        entered = asyncio.Event()

        async def request() -> None:
            async with runtime.request_scope():
                entered.set()
                await asyncio.Event().wait()

        request_task = asyncio.create_task(request())
        await entered.wait()
        await runtime.close(grace_period=0.01)

        with pytest.raises(asyncio.CancelledError):
            await request_task

    asyncio.run(exercise())


def test_shutdown_request_wakes_the_foreground_waiter(tmp_path: Path) -> None:
    """A signal callback can wake the foreground service loop."""

    async def exercise() -> None:
        runtime = ServiceRuntime(
            bind="127.0.0.1",
            port=0,
            exported_environment=runtime_environment(
                tmp_path,
                tmp_path / "state.sqlite3",
            ),
            event_sink=MemoryEventSink(),
        )
        await runtime.start()
        waiter = asyncio.create_task(runtime.wait_for_shutdown())
        runtime.request_shutdown()
        await waiter
        await runtime.close()

    asyncio.run(exercise())


def test_control_waiter_distinguishes_reload_from_shutdown(tmp_path: Path) -> None:
    """The foreground loop can process SIGHUP without stopping."""

    async def exercise() -> None:
        runtime = ServiceRuntime(
            bind="127.0.0.1",
            port=0,
            exported_environment=runtime_environment(
                tmp_path,
                tmp_path / "state.sqlite3",
            ),
            event_sink=MemoryEventSink(),
        )
        await runtime.start()
        runtime.request_reload()
        assert await runtime.wait_for_control_event() == "reload"
        runtime.request_shutdown()
        assert await runtime.wait_for_control_event() == "shutdown"
        await runtime.close()

    asyncio.run(exercise())
