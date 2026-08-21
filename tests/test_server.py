"""Behavioural tests for the application-owned issuer listener."""

from __future__ import annotations

import asyncio
import socket
from typing import Any

import asyncssh
import pytest

from ski.server import IssuerServer


def test_issuer_starts_with_an_application_owned_listener() -> None:
    """A started issuer reports an application-owned listener."""

    async def exercise() -> None:
        issuer = IssuerServer(bind="127.0.0.1", port=0)
        await issuer.start()
        try:
            assert issuer.port > 0
            assert issuer.addresses
        finally:
            await issuer.close()

    asyncio.run(exercise())


def test_wildcard_issuer_binds_both_ip_families() -> None:
    """The wildcard service owns explicit IPv4 and IPv6 listeners."""

    async def exercise() -> None:
        issuer = IssuerServer(bind="*", port=0)
        await issuer.start()
        try:
            hosts = {address[0] for address in issuer.addresses}
            assert "0.0.0.0" in hosts
            assert "::" in hosts
        finally:
            await issuer.close()

    asyncio.run(exercise())


def test_wildcard_bind_failure_closes_the_listener_already_opened() -> None:
    """A partial wildcard bind never leaves a live first-family listener."""

    class FakeAcceptor:
        def __init__(self, host: str, port: int) -> None:
            self.host = host
            self.port = port
            self.closed = False

        def get_addresses(self) -> list[tuple[str, int]]:
            return [(self.host, self.port)]

        def get_port(self) -> int:
            return self.port

        def close(self) -> None:
            self.closed = True

        async def wait_closed(self) -> None:
            return

    async def exercise() -> None:
        opened: list[FakeAcceptor] = []

        async def listen(host: str, port: int, **_: Any) -> FakeAcceptor:
            if host == "::":
                raise OSError("IPv6 bind failed")
            acceptor = FakeAcceptor(host, port)
            opened.append(acceptor)
            return acceptor

        issuer = IssuerServer(bind="*", port=2222, listener_factory=listen)
        with pytest.raises(OSError, match="IPv6 bind failed"):
            await issuer.start()

        assert opened[0].closed
        assert issuer.addresses == []

    asyncio.run(exercise())


def test_issuer_accepts_a_specific_ipv6_address() -> None:
    """A specific IPv6 bind remains a single application-owned listener."""
    if not socket.has_ipv6:
        pytest.skip("IPv6 is unavailable")

    async def exercise() -> None:
        issuer = IssuerServer(bind="::1", port=0)
        await issuer.start()
        try:
            assert {address[0] for address in issuer.addresses} == {"::1"}
        finally:
            await issuer.close()

    asyncio.run(exercise())


def test_issuer_closes_when_serve_is_cancelled() -> None:
    """Cancelling the foreground runtime releases its listener."""

    async def exercise() -> None:
        issuer = IssuerServer(bind="127.0.0.1", port=0)
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


def test_issuer_rejects_exec_requests() -> None:
    """The issuer does not expose arbitrary command execution."""

    async def exercise() -> None:
        issuer = IssuerServer(bind="127.0.0.1", port=0)
        await issuer.start()
        try:
            async with asyncssh.connect(
                "127.0.0.1",
                port=issuer.port,
                username="test-user",
                known_hosts=None,
                agent_forwarding=False,
            ) as connection:
                with pytest.raises(asyncssh.ChannelOpenError):
                    await connection.create_process(
                        command="unexpected-command",
                        request_pty=False,
                    )
        finally:
            await issuer.close()

    asyncio.run(exercise())


def test_issuer_rejects_direct_tcp_forwarding() -> None:
    """The issuer does not expose direct TCP forwarding."""

    async def exercise() -> None:
        issuer = IssuerServer(bind="127.0.0.1", port=0)
        await issuer.start()
        try:
            async with asyncssh.connect(
                "127.0.0.1",
                port=issuer.port,
                username="test-user",
                known_hosts=None,
                agent_forwarding=False,
            ) as connection:
                with pytest.raises(asyncssh.ChannelOpenError):
                    await connection.open_connection("127.0.0.1", 1)
        finally:
            await issuer.close()

    asyncio.run(exercise())
