"""Foreground signal and control-event coordination."""

from __future__ import annotations

import asyncio
import signal
from collections.abc import Callable
from typing import Literal

ControlEvent = Literal["shutdown", "reload"]


class RuntimeControl:
    """Coordinate service signals without owning service resources."""

    def __init__(self) -> None:
        self._shutdown_requested = asyncio.Event()
        self._reload_requested = asyncio.Event()

    def request_shutdown(self) -> None:
        """Request foreground shutdown from a signal or control caller."""
        self._shutdown_requested.set()

    def request_reload(self) -> None:
        """Request a serialized configuration reload from a signal caller."""
        self._reload_requested.set()

    def install_signal_handlers(
        self,
        loop: asyncio.AbstractEventLoop | None = None,
    ) -> Callable[[], None]:
        """Install SIGTERM/SIGINT/SIGHUP handlers and return their removal callback."""
        event_loop = asyncio.get_running_loop() if loop is None else loop
        installed: list[int] = []
        signals = [signal.SIGTERM, signal.SIGINT]
        if hasattr(signal, "SIGHUP"):
            signals.append(signal.SIGHUP)
        for signum in signals:
            try:
                callback = (
                    self.request_reload
                    if signum == signal.SIGHUP
                    else self.request_shutdown
                )
                event_loop.add_signal_handler(signum, callback)
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

    async def wait_for_control_event(self) -> ControlEvent:
        """Wait for either a reload or terminal shutdown request."""
        shutdown = asyncio.create_task(self._shutdown_requested.wait())
        reload_request = asyncio.create_task(self._reload_requested.wait())
        done, pending = await asyncio.wait(
            (shutdown, reload_request),
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        if shutdown in done:
            return "shutdown"
        self._reload_requested.clear()
        return "reload"
