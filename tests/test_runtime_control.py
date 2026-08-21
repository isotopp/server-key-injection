"""Behavioural tests for foreground control coordination."""

from __future__ import annotations

import asyncio
import signal
from typing import cast

from ski.control import RuntimeControl


def test_shutdown_control_wakes_waiter() -> None:
    """A shutdown request wakes the dedicated control boundary."""

    async def exercise() -> None:
        control = RuntimeControl()
        waiter = asyncio.create_task(control.wait_for_shutdown())
        control.request_shutdown()
        await waiter

    asyncio.run(exercise())


def test_reload_control_is_consumed_before_next_event() -> None:
    """A reload event is returned once and does not remain latched."""

    async def exercise() -> None:
        control = RuntimeControl()
        control.request_reload()
        assert await control.wait_for_control_event() == "reload"
        waiter = asyncio.create_task(control.wait_for_control_event())
        control.request_shutdown()
        assert await waiter == "shutdown"

    asyncio.run(exercise())


def test_signal_handlers_can_be_removed() -> None:
    """Signal installation is reversible and binds the expected callbacks."""

    class FakeLoop:
        def __init__(self) -> None:
            self.added: list[tuple[int, object]] = []
            self.removed: list[int] = []

        def add_signal_handler(self, signum: int, callback: object) -> None:
            self.added.append((signum, callback))

        def remove_signal_handler(self, signum: int) -> None:
            self.removed.append(signum)

    control = RuntimeControl()
    loop = FakeLoop()
    remove = control.install_signal_handlers(cast(asyncio.AbstractEventLoop, loop))

    expected = {signal.SIGTERM, signal.SIGINT}
    if hasattr(signal, "SIGHUP"):
        expected.add(signal.SIGHUP)
    assert {signum for signum, _ in loop.added} == expected
    remove()
    assert set(loop.removed) == expected
