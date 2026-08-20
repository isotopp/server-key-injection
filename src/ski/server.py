"""Runtime for the in-memory test issuer."""

from __future__ import annotations

import asyncio
from typing import Any

import asyncssh


class _TestSSHServer(asyncssh.SSHServer):
    """Permit the unauthenticated SSH handshake used by the tracer."""

    def begin_auth(self, username: str) -> bool:
        """Skip authentication; the tracer has no identity store yet."""
        del username
        return False


class TracerIssuer:
    """Manage the disposable AsyncSSH listener used by tracer tests."""

    def __init__(self, *, bind: str = "*", port: int = 22) -> None:
        self.bind = bind
        self.requested_port = port
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
        self._acceptor = await asyncssh.listen(
            listen_host,
            self.requested_port,
            server_factory=_TestSSHServer,
            server_host_keys=[host_key],
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
