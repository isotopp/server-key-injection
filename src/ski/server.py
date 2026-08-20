"""Runtime for the in-memory test issuer."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any, cast

import asyncssh

TracerRequestHandler = Callable[[asyncssh.SSHServerConnection], Awaitable[None]]


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

        if self._request_handler is not None:
            await self._request_handler(
                cast(asyncssh.SSHServerConnection, self._channel.get_connection())
            )

        self._channel.write("Tracer request accepted.\n")
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
    ) -> None:
        self.bind = bind
        self.requested_port = port
        self.request_handler = request_handler
        self._acceptor: asyncssh.SSHAcceptor | None = None

    @property
    def addresses(self) -> list[tuple[Any, ...]]:
        """Return the listener's bound socket addresses."""
        if self._acceptor is None:
            return []
        return self._acceptor.get_addresses()

    @property
    def port(self) -> int:
        """Return the active listener port, or zero before startup."""
        if self._acceptor is None:
            return 0
        return self._acceptor.get_port()

    async def start(self) -> None:
        """Start the listener with a process-local ephemeral host key."""
        if self._acceptor is not None:
            raise RuntimeError("test issuer is already running")

        listen_host = "" if self.bind == "*" else self.bind
        host_key = asyncssh.generate_private_key("ssh-ed25519")

        def server_factory() -> _TracerSSHServer:
            return _TracerSSHServer(self.request_handler)

        self._acceptor = await asyncssh.listen(
            listen_host,
            self.requested_port,
            server_factory=server_factory,
            server_host_keys=[host_key],
            agent_forwarding=True,
        )

    async def serve(self) -> None:
        """Run until cancelled, then close the listener."""
        await self.start()
        try:
            await asyncio.Event().wait()
        finally:
            await self.close()

    async def close(self) -> None:
        """Stop accepting connections and release the listener."""
        if self._acceptor is None:
            return

        acceptor = self._acceptor
        self._acceptor = None
        acceptor.close()
        await acceptor.wait_closed()
