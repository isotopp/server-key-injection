"""Foreground service runtime orchestration."""

from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import asyncssh

from ski.ca import ValidatedActiveCA, load_validated_active_ca
from ski.configuration import (
    ConfigurationError,
    RuntimeConfiguration,
    load_runtime_configuration,
)
from ski.control import RuntimeControl
from ski.credentials import OrdinaryIssuanceService
from ski.identities import IdentitySnapshot, SqliteIdentityStore
from ski.injection import OrdinaryAgentInjector, TracerAgentInjector
from ski.journal import ConsoleEventSink, Event, JournalEventSink, MemoryEventSink
from ski.request_processing import AuthenticatedRequestProcessor
from ski.server import TracerIssuer
from ski.state import StateDatabase

EventSink = MemoryEventSink | ConsoleEventSink | JournalEventSink
StateOpener = Callable[..., StateDatabase]
IssuerFactory = Callable[..., TracerIssuer]
DEFAULT_SHUTDOWN_GRACE_PERIOD = 5.0


@dataclass(frozen=True, slots=True)
class RuntimeResources:
    """One immutable, fully acquired set of resources visible to requests."""

    configuration: RuntimeConfiguration
    state: StateDatabase
    active_ca: ValidatedActiveCA
    issuer: TracerIssuer
    ordinary_injector: OrdinaryAgentInjector
    request_processor: AuthenticatedRequestProcessor


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
        self._resources: RuntimeResources | None = None
        self._configuration_generation = 0
        self._in_flight: set[asyncio.Task[Any]] = set()
        self._stopping = False
        self._close_started = False
        self._close_complete = asyncio.Event()
        self._reload_lock = asyncio.Lock()
        self._control = RuntimeControl()
        self._injector = TracerAgentInjector()

    @property
    def configuration(self) -> RuntimeConfiguration:
        """Return the active immutable configuration snapshot."""
        resources = self._resources
        if resources is None:
            raise RuntimeError("service runtime is not started")
        return resources.configuration

    @property
    def state(self) -> StateDatabase:
        """Return the active local state handle."""
        resources = self._resources
        if resources is None:
            raise RuntimeError("service runtime is not started")
        return resources.state

    @property
    def issuer(self) -> TracerIssuer:
        """Return the active tracer issuer."""
        resources = self._resources
        if resources is None:
            raise RuntimeError("service runtime is not started")
        return resources.issuer

    @property
    def active_ca(self) -> ValidatedActiveCA:
        """Return the validated persistent CA used by this runtime."""
        resources = self._resources
        if resources is None:
            raise RuntimeError("service runtime is not started")
        return resources.active_ca

    @property
    def configuration_generation(self) -> int:
        """Return the generation number of the active configuration."""
        return self._configuration_generation

    async def start(self) -> None:
        """Start all resources, or unwind every resource acquired so far."""
        if self._resources is not None:
            raise RuntimeError("service runtime is already running")

        self._emit("service_starting", "ski startup requested")
        state: StateDatabase | None = None
        issuer: TracerIssuer | None = None
        try:
            configuration = load_runtime_configuration(
                bind=self.bind,
                port=self.port,
                exported_environment=self._exported_environment,
                allow_ephemeral_port=self.port == 0,
            )
            state = self._state_opener(configuration.database, owner=True)
            host_key = asyncssh.import_private_key(state.host_key.private_key)
            if (
                configuration.ca_private_key is None
                or configuration.ca_public_key is None
            ):
                raise ConfigurationError("ordinary CA configuration is incomplete")
            active_ca = load_validated_active_ca(
                state,
                private_path=configuration.ca_private_key,
                public_path=configuration.ca_public_key,
            )
            ordinary_injector = OrdinaryAgentInjector(
                OrdinaryIssuanceService(
                    state,
                    active_ca,
                    extensions=configuration.ordinary_extensions,
                ),
            )
            request_processor = AuthenticatedRequestProcessor(
                ordinary_injector,
                event_sink=self._event_sink,
                request_scope=self.request_scope,
            )
            identity_store = SqliteIdentityStore(state)
            issuer = self._issuer_factory(
                bind=configuration.bind,
                port=configuration.port,
                request_handler=self._handle_tracer_request,
                authenticated_request_handler=self._handle_authenticated_tracer_request,
                server_host_key=host_key,
                identity_store=identity_store,
                active_ca=active_ca,
            )
            await issuer.start()
            self._resources = RuntimeResources(
                configuration=configuration,
                state=state,
                active_ca=active_ca,
                issuer=issuer,
                ordinary_injector=ordinary_injector,
                request_processor=request_processor,
            )
            self._configuration_generation = 1
        except Exception as exc:
            await self._close_partial_resources(issuer, state)
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

    async def reload(self) -> bool:
        """Serialize configuration reload attempts."""
        async with self._reload_lock:
            return await self._reload_once()

    async def _reload_once(self) -> bool:
        """Validate and atomically adopt a reloadable configuration candidate."""
        resources = self._resources
        if resources is None:
            raise RuntimeError("service runtime is not started")

        self._emit("service_reload_started", "ski configuration reload requested")
        try:
            candidate = load_runtime_configuration(
                bind=self.bind,
                port=self.port,
                exported_environment=self._exported_environment,
                allow_ephemeral_port=self.port == 0,
            )
            if candidate.database != resources.configuration.database:
                raise ConfigurationError("restart required for database path change")
            if (
                candidate.ca_private_key != resources.configuration.ca_private_key
                or candidate.ca_public_key != resources.configuration.ca_public_key
                or candidate.ca_krl != resources.configuration.ca_krl
            ):
                raise ConfigurationError("restart required for CA path change")
        except Exception as exc:
            error_code = (
                "restart_required"
                if isinstance(exc, ConfigurationError)
                and str(exc).startswith("restart required")
                else type(exc).__name__
            )
            self._emit(
                "service_reload_rejected",
                "ski configuration reload rejected",
                fields={"SKI_ERROR_CODE": error_code},
                priority=4,
            )
            return False

        self._resources = RuntimeResources(
            configuration=candidate,
            state=resources.state,
            active_ca=resources.active_ca,
            issuer=resources.issuer,
            ordinary_injector=resources.ordinary_injector,
            request_processor=resources.request_processor,
        )
        self._configuration_generation += 1
        self._emit(
            "service_reload_accepted",
            "ski configuration reload accepted",
            fields={"SKI_CONFIG_GENERATION": str(self._configuration_generation)},
        )
        return True

    async def close(
        self,
        *,
        grace_period: float = DEFAULT_SHUTDOWN_GRACE_PERIOD,
    ) -> None:
        """Close listeners, drain requests, and release ownership."""
        if self._close_started:
            await self._close_complete.wait()
            return
        resources = self._resources
        if resources is None:
            return

        self._close_started = True
        self._stopping = True
        self._resources = None
        self._emit("service_stopping", "ski shutdown requested")
        try:
            await resources.issuer.close()
            await self._drain_requests(grace_period)
        finally:
            resources.state.close()
            self._configuration_generation = 0
            self._emit("service_stopped", "ski shutdown complete")
            self._close_complete.set()

    @asynccontextmanager
    async def request_scope(self) -> AsyncIterator[RuntimeConfiguration]:
        """Track one admitted request until it finishes or is cancelled."""
        if self._stopping or self._resources is None:
            raise RuntimeError("service runtime is stopping or not started")
        task = asyncio.current_task()
        if task is None:
            raise RuntimeError("request scope requires an asyncio task")
        self._in_flight.add(task)
        try:
            yield self.configuration
        finally:
            self._in_flight.discard(task)

    def request_shutdown(self) -> None:
        """Request foreground shutdown from a signal handler."""
        self._control.request_shutdown()

    def request_reload(self) -> None:
        """Request a serialized configuration reload from a signal handler."""
        self._control.request_reload()

    def install_signal_handlers(
        self,
        loop: asyncio.AbstractEventLoop | None = None,
    ) -> Callable[[], None]:
        """Install SIGTERM/SIGINT handlers and return their removal callback."""
        return self._control.install_signal_handlers(loop)

    async def wait_for_shutdown(self) -> None:
        """Wait until a foreground shutdown signal has been requested."""
        await self._control.wait_for_shutdown()

    async def wait_for_control_event(self) -> str:
        """Wait for either a reload or terminal shutdown request."""
        return await self._control.wait_for_control_event()

    async def _handle_tracer_request(
        self,
        connection: Any,
    ) -> str | None:
        async with self.request_scope():
            return await self._injector.handle(connection)

    async def _handle_authenticated_tracer_request(
        self,
        connection: Any,
        identity: IdentitySnapshot,
    ) -> str | None:
        resources = self._resources
        if resources is None:
            raise RuntimeError("ordinary request processor is unavailable")
        return await resources.request_processor.handle(connection, identity)

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

    async def _close_partial_resources(
        self,
        issuer: TracerIssuer | None,
        state: StateDatabase | None,
    ) -> None:
        """Close resources acquired before the immutable bundle became visible."""
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
