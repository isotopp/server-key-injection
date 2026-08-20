"""Behavioural tests for the test issuer runtime."""

from __future__ import annotations

import asyncio

import asyncssh

from ski.server import TracerIssuer


def test_test_issuer_accepts_a_local_ssh_handshake() -> None:
    """A started test issuer accepts a real SSH connection."""

    async def exercise() -> None:
        issuer = TracerIssuer(bind="127.0.0.1", port=0)
        await issuer.start()
        try:
            assert issuer.port > 0
            async with asyncssh.connect(
                "127.0.0.1",
                port=issuer.port,
                username="test-user",
                known_hosts=None,
            ):
                assert issuer.addresses
        finally:
            await issuer.close()

    asyncio.run(exercise())


def test_test_issuer_closes_when_serve_is_cancelled() -> None:
    """Cancelling the foreground runtime releases its listener."""

    async def exercise() -> None:
        issuer = TracerIssuer(bind="127.0.0.1", port=0)
        task = asyncio.create_task(issuer.serve())
        for _ in range(100):
            if issuer.port > 0:
                break
            await asyncio.sleep(0)

        assert issuer.port > 0
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        assert issuer.addresses == []

    asyncio.run(exercise())
