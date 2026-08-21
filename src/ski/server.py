"""Runtime for the in-memory test issuer."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any, cast

import asyncssh

TracerRequestHandler = Callable[[asyncssh.SSHServerConnection], Awaitable[str | None]]
ListenerFactory = Callable[..., Awaitable[Any]]


class _TracerSession(asyncssh.SSHServerSession):
    """Handle the one interactive session exposed by the tracer."""

    def __init__(self, request_handler: TracerRequestHandler | None) -> None:
        self._request_handler = request_handler
        self._channel: asyncssh.SSHServerChannel | None = None

    def connection_made(self, chan: asyncssh.SSHServerChannel) -> None:
        self._channel = chan

    def shell_requested(self) -> bool:
        return True

    def session_started(self) -> None:
        assert self._channel is not None
        self._channel.get_loop().create_task(self._run_request())

    async def _run_request(self) -> None:
        assert self._channel is not None
        agent_path = self._channel.get_agent_path()
        if agent_path is None:
            self._channel.write_stderr("Agent forwarding is required.\n")
            self._channel.exit(1)
            return

        result: str | None = None
        if self._request_handler is not None:
            try:
                result = await self._request_handler(
                    cast(
                        asyncssh.SSHServerConnection,
                        self._channel.get_connection(),
                    )
                )
            except Exception:  # pragma: no cover - exercised by integration
                self._channel.write_stderr("Tracer request failed.\n")
                self._channel.exit(1)
                return

        if result is None:
            self._channel.write("Tracer request accepted.\n")
        else:
            self._channel.write(f"Key loaded: {result}\n")
        self._channel.exit(0)


class _TracerSSHServer(asyncssh.SSHServer):
    """Permit the unauthenticated SSH handshake used by the tracer."""

    def __init__(self, request_handler: TracerRequestHandler | None) -> None:
        self._request_handler = request_handler

    def begin_auth(self, username: str) -> bool:
        """Skip authentication; the tracer has no identity store yet."""
        del username
        return False

    def session_requested(self) -> _TracerSession:
        return _TracerSession(self._request_handler)


class TracerIssuer:
    """Manage the disposable AsyncSSH listener used by tracer tests."""

    def __init__(
        self,
        *,
        bind: str = "*",
        port: int = 22,
        request_handler: TracerRequestHandler | None = None,
        listener_factory: ListenerFactory | None = None,
    ) -> None:
        self.bind = bind
        self.requested_port = port
        self.request_handler = request_handler
        self._listener_factory = (
            asyncssh.listen if listener_factory is None else listener_factory
        )
        self._acceptors: list[Any] = []

    @property
    def addresses(self) -> list[tuple[Any, ...]]:
        """Return the listener's bound socket addresses."""
        return [
            address
            for acceptor in self._acceptors
            for address in acceptor.get_addresses()
        ]

    @property
    def port(self) -> int:
        """Return the active listener port, or zero before startup."""
        if not self._acceptors:
            return 0
        return self._acceptors[0].get_port()

    async def start(self) -> None:
        """Start the listener with a process-local ephemeral host key."""
        if self._acceptors:
            raise RuntimeError("test issuer is already running")

        host_key = asyncssh.generate_private_key("ssh-ed25519")
        hosts = ("0.0.0.0", "::") if self.bind == "*" else (self.bind,)

        def server_factory() -> _TracerSSHServer:
            return _TracerSSHServer(self.request_handler)

        opened: list[Any] = []
        port = self.requested_port
        try:
            for host in hosts:
                acceptor = await self._listener_factory(
                    host,
                    port,
                    server_factory=server_factory,
                    server_host_keys=[host_key],
                    agent_forwarding=True,
                )
                opened.append(acceptor)
                if port == 0:
                    port = acceptor.get_port()
        except Exception:
            await self._close_acceptors(opened)
            raise
        self._acceptors = opened

    async def serve(self) -> None:
        """Run until cancelled, then close the listener."""
        await self.start()
        try:
            await asyncio.Event().wait()
        finally:
            await self.close()

    async def close(self) -> None:
        """Stop accepting connections and release the listener."""
        if not self._acceptors:
            return

        acceptors = self._acceptors
        self._acceptors = []
        await self._close_acceptors(acceptors)

    @staticmethod
    async def _close_acceptors(acceptors: list[Any]) -> None:
        for acceptor in acceptors:
            acceptor.close()
        await asyncio.gather(*(acceptor.wait_closed() for acceptor in acceptors))
