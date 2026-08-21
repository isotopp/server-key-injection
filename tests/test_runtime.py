"""Behavioural tests for the ordered service runtime."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import cast

import pytest

from ski.journal import MemoryEventSink
from ski.runtime import IssuerFactory, ServiceRuntime, StateOpener
from ski.state import StateDatabase


def test_service_runtime_starts_state_and_listener_before_ready_event(
    tmp_path: Path,
) -> None:
    """A ready event follows complete state and listener initialization."""

    async def exercise() -> None:
        sink = MemoryEventSink()
        runtime = ServiceRuntime(
            bind="127.0.0.1",
            port=0,
            exported_environment={"SKI_CA_DATABASE": str(tmp_path / "state.sqlite3")},
            event_sink=sink,
        )
        await runtime.start()
        try:
            assert runtime.state.schema_version == 1
            assert runtime.issuer.port > 0
            ready = sink.events[-1]
            assert ready.name == "service_ready"
            assert ready.fields["SKI_PORT"] == str(runtime.issuer.port)
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
            exported_environment={"SKI_CA_DATABASE": str(tmp_path / "state.sqlite3")},
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
            exported_environment={"SKI_CA_DATABASE": str(database_path)},
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
            exported_environment={"SKI_CA_DATABASE": str(database_path)},
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
            exported_environment={"SKI_CA_DATABASE": str(tmp_path / "state.sqlite3")},
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
            exported_environment={"SKI_CA_DATABASE": str(tmp_path / "state.sqlite3")},
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
            exported_environment={"SKI_CA_DATABASE": str(tmp_path / "state.sqlite3")},
            event_sink=MemoryEventSink(),
        )
        await runtime.start()
        waiter = asyncio.create_task(runtime.wait_for_shutdown())
        runtime.request_shutdown()
        await waiter
        await runtime.close()

    asyncio.run(exercise())
