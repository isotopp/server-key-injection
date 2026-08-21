"""AsyncSSH listener for authenticated ordinary certificate issuance."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Sequence
from typing import Any, cast

import asyncssh

from ski.ca import ValidatedActiveCA
from ski.identities import IdentitySnapshot, IssuerIdentityProvider

AuthenticatedRequestHandler = Callable[
    [asyncssh.SSHServerConnection, IdentitySnapshot], Awaitable[str | None]
]
ListenerFactory = Callable[..., Awaitable[Any]]


class _IssuerSession(asyncssh.SSHServerSession):
    """Handle one agent-backed ordinary certificate request."""

    def __init__(
        self,
        authenticated_request_handler: AuthenticatedRequestHandler | None,
        identity: IdentitySnapshot,
    ) -> None:
        self._authenticated_request_handler = authenticated_request_handler
        self.identity = identity
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
        connection = cast(
            asyncssh.SSHServerConnection,
            self._channel.get_connection(),
        )
        if self._authenticated_request_handler is not None:
            try:
                result = await self._authenticated_request_handler(
                    connection,
                    self.identity,
                )
            except Exception:  # pragma: no cover - exercised by integration
                self._channel.write_stderr("Certificate request failed.\n")
                self._channel.exit(1)
                return

        if result is None:
            self._channel.write("Certificate request accepted.\n")
        else:
            self._channel.write(f"Key loaded: {result}\n")
        groups = ", ".join(self.identity.groups) or "(none)"
        self._channel.write(f"Groups: {groups}\n")
        self._channel.exit(0)


class _IssuerSSHServer(asyncssh.SSHServer):
    """Handle one password-plus-TOTP identity exchange."""

    def __init__(
        self,
        authenticated_request_handler: AuthenticatedRequestHandler | None,
        identity_store: IssuerIdentityProvider | None,
        clock: Callable[[], float],
    ) -> None:
        self._authenticated_request_handler = authenticated_request_handler
        self._identity_store = identity_store
        self._clock = clock
        self._connection: asyncssh.SSHServerConnection | None = None
        self._username: str | None = None
        self._exchange_attempted = False
        self._authenticated_identity: IdentitySnapshot | None = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        """Retain the connection only to terminate a failed MFA exchange."""
        self._connection = conn

    def begin_auth(self, username: str) -> bool:
        """Require one keyboard-interactive exchange when identities are enabled."""
        self._username = username
        return self._identity_store is not None

    def kbdint_auth_supported(self) -> bool:
        """Advertise keyboard-interactive auth for configured identities."""
        return self._identity_store is not None

    def get_kbdint_challenge(
        self,
        username: str,
        lang: str,
        submethods: str,
    ) -> tuple[str, str, str, tuple[tuple[str, bool], ...]] | bool:
        """Issue exactly one combined password and TOTP challenge."""
        del lang, submethods
        if (
            self._identity_store is None
            or self._exchange_attempted
            or self._username != username
        ):
            return False
        self._exchange_attempted = True
        return (
            "ski",
            "Authenticate with your ski password and TOTP code.",
            "",
            (("Password:", False), ("2FA:", False)),
        )

    def validate_kbdint_response(
        self,
        username: str,
        responses: Sequence[str],
    ) -> bool:
        """Verify both factors and bind a current group snapshot on success."""
        if self._identity_store is None or not self._exchange_attempted:
            return False
        if self._username != username or len(responses) != 2:
            if self._connection is not None:
                self._connection.abort()
            return False
        try:
            canonical_username = self._identity_store.lookup_identity(username)
            password_ok = self._identity_store.verify_password(
                canonical_username,
                responses[0],
            )
            totp_ok = self._identity_store.verify_totp(
                canonical_username,
                responses[1],
                now=int(self._clock()),
            )
            if not password_ok or not totp_ok:
                if self._connection is not None:
                    self._connection.abort()
                return False
            self._authenticated_identity = self._identity_store.get_group_snapshot(
                canonical_username,
            )
            return True
        except Exception:
            if self._connection is not None:
                self._connection.abort()
            return False

    def session_requested(self) -> _IssuerSession | bool:
        if self._identity_store is None or self._authenticated_identity is None:
            return False
        return _IssuerSession(
            self._authenticated_request_handler,
            self._authenticated_identity,
        )


class IssuerServer:
    """Manage the application-owned AsyncSSH issuer listener."""

    def __init__(
        self,
        *,
        bind: str = "*",
        port: int = 22,
        authenticated_request_handler: AuthenticatedRequestHandler | None = None,
        listener_factory: ListenerFactory | None = None,
        server_host_key: asyncssh.SSHKey | None = None,
        identity_store: IssuerIdentityProvider | None = None,
        active_ca: ValidatedActiveCA | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.bind = bind
        self.requested_port = port
        self.authenticated_request_handler = authenticated_request_handler
        self.identity_store = identity_store
        self.active_ca = active_ca
        self._clock = clock
        self._server_host_key = (
            asyncssh.generate_private_key("ssh-ed25519")
            if server_host_key is None
            else server_host_key
        )
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
        """Start the listener with the configured host key."""
        if self._acceptors:
            raise RuntimeError("issuer is already running")

        hosts = ("0.0.0.0", "::") if self.bind == "*" else (self.bind,)

        def server_factory() -> _IssuerSSHServer:
            return _IssuerSSHServer(
                self.authenticated_request_handler,
                self.identity_store,
                self._clock,
            )

        opened: list[Any] = []
        port = self.requested_port
        try:
            for host in hosts:
                acceptor = await self._listener_factory(
                    host,
                    port,
                    server_factory=server_factory,
                    server_host_keys=[self._server_host_key],
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
