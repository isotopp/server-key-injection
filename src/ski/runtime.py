"""Foreground service runtime orchestration."""

from __future__ import annotations

import asyncio
import os
import signal
import sys
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from typing import Any

from ski.configuration import RuntimeConfiguration, load_runtime_configuration
from ski.injection import TracerAgentInjector
from ski.journal import ConsoleEventSink, Event, JournalEventSink, MemoryEventSink
from ski.server import TracerIssuer
from ski.state import StateDatabase

EventSink = MemoryEventSink | ConsoleEventSink | JournalEventSink
StateOpener = Callable[..., StateDatabase]
IssuerFactory = Callable[..., TracerIssuer]
DEFAULT_SHUTDOWN_GRACE_PERIOD = 5.0


def default_event_sink() -> EventSink:
    """Select journald on Linux and console output elsewhere."""
    if sys.platform == "linux":
        return JournalEventSink()
    return ConsoleEventSink()


class ServiceRuntime:
    """Acquire, expose, and release the issuer's local service resources."""

    def __init__(
        self,
        *,
        bind: str,
        port: int,
        exported_environment: Mapping[str, str] | None = None,
        event_sink: EventSink | None = None,
        state_opener: StateOpener = StateDatabase.open,
        issuer_factory: IssuerFactory = TracerIssuer,
    ) -> None:
        self.bind = bind
        self.port = port
        self._exported_environment = dict(
            os.environ if exported_environment is None else exported_environment,
        )
        self._event_sink = default_event_sink() if event_sink is None else event_sink
        self._state_opener = state_opener
        self._issuer_factory = issuer_factory
        self._configuration: RuntimeConfiguration | None = None
        self._state: StateDatabase | None = None
        self._issuer: TracerIssuer | None = None
        self._in_flight: set[asyncio.Task[Any]] = set()
        self._stopping = False
        self._close_started = False
        self._close_complete = asyncio.Event()
        self._shutdown_requested = asyncio.Event()
        self._injector = TracerAgentInjector()

    @property
    def configuration(self) -> RuntimeConfiguration:
        """Return the active immutable configuration snapshot."""
        if self._configuration is None:
            raise RuntimeError("service runtime is not started")
        return self._configuration

    @property
    def state(self) -> StateDatabase:
        """Return the active local state handle."""
        if self._state is None:
            raise RuntimeError("service runtime is not started")
        return self._state

    @property
    def issuer(self) -> TracerIssuer:
        """Return the active tracer issuer."""
        if self._issuer is None:
            raise RuntimeError("service runtime is not started")
        return self._issuer

    async def start(self) -> None:
        """Start all resources, or unwind every resource acquired so far."""
        if self._issuer is not None or self._state is not None:
            raise RuntimeError("service runtime is already running")

        self._emit("service_starting", "ski startup requested")
        try:
            configuration = load_runtime_configuration(
                bind=self.bind,
                port=self.port,
                exported_environment=self._exported_environment,
                allow_ephemeral_port=self.port == 0,
            )
            state = self._state_opener(configuration.database, owner=True)
            issuer = self._issuer_factory(
                bind=configuration.bind,
                port=configuration.port,
                request_handler=self._handle_tracer_request,
            )
            self._state = state
            self._issuer = issuer
            await issuer.start()
            self._configuration = configuration
        except Exception as exc:
            await self._cleanup_resources()
            self._emit(
                "service_start_failed",
                "ski startup failed",
                fields={"SKI_ERROR_CODE": type(exc).__name__},
                priority=3,
            )
            raise

        self._emit(
            "service_ready",
            "ski is ready",
            fields={
                "SKI_ADDRESSES": ",".join(
                    str(address) for address in self.issuer.addresses
                ),
                "SKI_BIND": configuration.bind,
                "SKI_PORT": str(self.issuer.port),
            },
        )

    async def close(
        self,
        *,
        grace_period: float = DEFAULT_SHUTDOWN_GRACE_PERIOD,
    ) -> None:
        """Close listeners, drain requests, and release ownership."""
        if self._issuer is None and self._state is None:
            return
        if self._close_started:
            await self._close_complete.wait()
            return

        self._close_started = True
        self._stopping = True
        self._emit("service_stopping", "ski shutdown requested")
        try:
            issuer, self._issuer = self._issuer, None
            if issuer is not None:
                await issuer.close()
            await self._drain_requests(grace_period)
        finally:
            state, self._state = self._state, None
            if state is not None:
                state.close()
            self._configuration = None
            self._emit("service_stopped", "ski shutdown complete")
            self._close_complete.set()

    @asynccontextmanager
    async def request_scope(self) -> AsyncIterator[None]:
        """Track one admitted request until it finishes or is cancelled."""
        if self._stopping or self._issuer is None:
            raise RuntimeError("service runtime is stopping or not started")
        task = asyncio.current_task()
        if task is None:
            raise RuntimeError("request scope requires an asyncio task")
        self._in_flight.add(task)
        try:
            yield
        finally:
            self._in_flight.discard(task)

    def request_shutdown(self) -> None:
        """Request foreground shutdown from a signal handler."""
        self._shutdown_requested.set()

    def install_signal_handlers(
        self,
        loop: asyncio.AbstractEventLoop | None = None,
    ) -> Callable[[], None]:
        """Install SIGTERM/SIGINT handlers and return their removal callback."""
        event_loop = asyncio.get_running_loop() if loop is None else loop
        installed: list[signal.Signals] = []
        for signum in (signal.SIGTERM, signal.SIGINT):
            try:
                event_loop.add_signal_handler(signum, self.request_shutdown)
            except (NotImplementedError, RuntimeError):
                continue
            installed.append(signum)

        def remove_handlers() -> None:
            for signum in installed:
                event_loop.remove_signal_handler(signum)

        return remove_handlers

    async def wait_for_shutdown(self) -> None:
        """Wait until a foreground shutdown signal has been requested."""
        await self._shutdown_requested.wait()

    async def _handle_tracer_request(
        self,
        connection: Any,
    ) -> str | None:
        async with self.request_scope():
            return await self._injector.handle(connection)

    async def _drain_requests(self, grace_period: float) -> None:
        tasks = set(self._in_flight)
        current = asyncio.current_task()
        if current is not None:
            tasks.discard(current)
        if not tasks:
            return
        _, pending = await asyncio.wait(tasks, timeout=grace_period)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

    async def _cleanup_resources(self) -> None:
        issuer, self._issuer = self._issuer, None
        state, self._state = self._state, None
        if issuer is not None:
            await issuer.close()
        if state is not None:
            state.close()

    def _emit(
        self,
        name: str,
        message: str,
        *,
        fields: Mapping[str, str] | None = None,
        priority: int = 6,
    ) -> None:
        self._event_sink.emit(
            Event(
                name=name,
                message=message,
                priority=priority,
                fields={} if fields is None else fields,
            ),
        )
