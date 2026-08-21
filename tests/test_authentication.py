"""Behavioural tests for issuer keyboard-interactive authentication."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from pathlib import Path
from typing import cast

import asyncssh
import pyotp
import pytest

from ski.identities import (
    IdentitySnapshot,
    IssuerIdentityProvider,
    SqliteIdentityStore,
)
from ski.journal import MemoryEventSink
from ski.runtime import ServiceRuntime
from ski.server import TracerIssuer
from ski.state import StateDatabase
from support import MfaClient as _MfaClient
from support import runtime_environment


def test_enabled_user_is_admitted_by_password_and_totp_challenge(
    tmp_path: Path,
) -> None:
    """A real client receives distinct factors and completes authentication."""
    database = StateDatabase.open(tmp_path / "state.sqlite3")
    issuer: TracerIssuer | None = None
    try:
        store = SqliteIdentityStore(database)
        user = store.create_user("alice", "password", "JBSWY3DPEHPK3PXP")
        client = _MfaClient("password", pyotp.TOTP(user.totp_secret).now())

        async def exercise() -> None:
            nonlocal issuer
            issuer = TracerIssuer(
                bind="127.0.0.1",
                port=0,
                identity_store=store,
            )
            await issuer.start()
            try:
                async with asyncssh.connect(
                    "127.0.0.1",
                    port=issuer.port,
                    username="alice",
                    known_hosts=None,
                    client_factory=lambda: client,
                    kbdint_auth=True,
                ):
                    pass
            finally:
                await issuer.close()

        asyncio.run(exercise())
        assert client.prompts == ("Password:", "2FA:")
    finally:
        database.close()


def test_authenticated_exchange_uses_only_read_identity_capabilities() -> None:
    """The SSH runtime accepts a backend without demo administration methods."""

    class ReadOnlyIdentityBackend:
        def lookup_identity(self, username: str) -> str:
            assert username == "alice"
            return username

        def verify_password(self, username: str, password: str) -> bool:
            return username == "alice" and password == "password"

        def verify_totp(
            self,
            username: str,
            code: str,
            *,
            now: int | None = None,
        ) -> bool:
            del now
            return username == "alice" and code == "123456"

        def get_group_snapshot(self, username: str) -> IdentitySnapshot:
            assert username == "alice"
            return IdentitySnapshot(username="alice", groups=("ops",))

    async def exercise() -> None:
        issuer = TracerIssuer(
            bind="127.0.0.1",
            port=0,
            identity_store=cast(IssuerIdentityProvider, ReadOnlyIdentityBackend()),
        )
        await issuer.start()
        try:
            async with asyncssh.connect(
                "127.0.0.1",
                port=issuer.port,
                username="alice",
                known_hosts=None,
                client_factory=lambda: _MfaClient("password", "123456"),
                kbdint_auth=True,
            ):
                pass
        finally:
            await issuer.close()

    asyncio.run(exercise())


def test_read_only_identity_backend_failure_is_a_uniform_denial() -> None:
    """A read backend failure never opens an authenticated SSH session."""

    class BrokenReadOnlyIdentityBackend:
        def lookup_identity(self, username: str) -> str:
            return username

        def verify_password(self, username: str, password: str) -> bool:
            del username, password
            raise RuntimeError("backend detail")

        def verify_totp(
            self,
            username: str,
            code: str,
            *,
            now: int | None = None,
        ) -> bool:
            del username, code, now
            return True

        def get_group_snapshot(self, username: str) -> IdentitySnapshot:
            return IdentitySnapshot(username=username, groups=())

    async def exercise() -> None:
        issuer = TracerIssuer(
            bind="127.0.0.1",
            port=0,
            identity_store=cast(
                IssuerIdentityProvider,
                BrokenReadOnlyIdentityBackend(),
            ),
        )
        await issuer.start()
        try:
            with pytest.raises((asyncssh.PermissionDenied, asyncssh.ConnectionLost)):
                async with asyncssh.connect(
                    "127.0.0.1",
                    port=issuer.port,
                    username="alice",
                    known_hosts=None,
                    client_factory=lambda: _MfaClient("password", "123456"),
                    kbdint_auth=True,
                ):
                    pass
        finally:
            await issuer.close()

    asyncio.run(exercise())


def test_service_runtime_wires_the_sqlite_identity_store_into_the_issuer(
    tmp_path: Path,
) -> None:
    """The foreground runtime uses the configured identity backend for auth."""
    database_path = tmp_path / "state.sqlite3"
    database = StateDatabase.open(database_path)
    try:
        user = SqliteIdentityStore(database).create_user(
            "alice",
            "password",
            "JBSWY3DPEHPK3PXP",
        )
    finally:
        database.close()
    client = _MfaClient("password", pyotp.TOTP(user.totp_secret).now())

    async def exercise() -> None:
        runtime = ServiceRuntime(
            bind="127.0.0.1",
            port=0,
            exported_environment=runtime_environment(tmp_path, database_path),
            event_sink=MemoryEventSink(),
        )
        await runtime.start()
        try:
            async with asyncssh.connect(
                "127.0.0.1",
                port=runtime.issuer.port,
                username="alice",
                known_hosts=None,
                client_factory=lambda: client,
                kbdint_auth=True,
            ):
                pass
        finally:
            await runtime.close()

    asyncio.run(exercise())
    assert client.prompts == ("Password:", "2FA:")


@pytest.mark.parametrize(
    "failure",
    ["unknown", "disabled", "password", "totp", "malformed", "store"],
)
def test_invalid_mfa_inputs_are_uniform_denials_before_session(
    failure: str,
    tmp_path: Path,
) -> None:
    """Every failed factor path denies authentication without opening a session."""
    database = StateDatabase.open(tmp_path / f"{failure}.sqlite3")
    requests = 0
    try:
        store = SqliteIdentityStore(database)
        if failure != "unknown":
            store.create_user("alice", "password", "JBSWY3DPEHPK3PXP")
            if failure == "disabled":
                store.set_user_enabled("alice", False)

        class FailingStore(SqliteIdentityStore):
            def verify_password(self, username: str, password: str) -> bool:
                raise RuntimeError("backend detail")

        identity_store = FailingStore(database) if failure == "store" else store
        username = "missing" if failure == "unknown" else "alice"
        password = "wrong" if failure == "password" else "password"
        code = "000000" if failure == "totp" else pyotp.TOTP("JBSWY3DPEHPK3PXP").now()

        class MalformedClient(_MfaClient):
            def kbdint_challenge_received(
                self,
                name: str,
                instructions: str,
                lang: str,
                prompts: Sequence[tuple[str, bool]],
            ) -> list[str]:
                return [self.password]

        client = (
            MalformedClient(password, code)
            if failure == "malformed"
            else _MfaClient(password, code)
        )

        async def exercise() -> None:
            nonlocal requests

            async def request_handler(
                _connection: asyncssh.SSHServerConnection,
            ) -> None:
                nonlocal requests
                requests += 1

            issuer = TracerIssuer(
                bind="127.0.0.1",
                port=0,
                identity_store=identity_store,
                request_handler=request_handler,
            )
            await issuer.start()
            try:
                with pytest.raises(
                    (asyncssh.PermissionDenied, asyncssh.ConnectionLost)
                ):
                    async with asyncssh.connect(
                        "127.0.0.1",
                        port=issuer.port,
                        username=username,
                        known_hosts=None,
                        client_factory=lambda: client,
                        kbdint_auth=True,
                    ):
                        pass
            finally:
                await issuer.close()

        asyncio.run(exercise())
        assert requests == 0
    finally:
        database.close()


def test_failed_exchange_requires_a_new_connection_for_retry(tmp_path: Path) -> None:
    """A denied connection cannot retry factors, but a fresh connection can."""
    database = StateDatabase.open(tmp_path / "state.sqlite3")
    try:
        store = SqliteIdentityStore(database)
        store.create_user("alice", "password", "JBSWY3DPEHPK3PXP")

        async def exercise() -> None:
            issuer = TracerIssuer(
                bind="127.0.0.1",
                port=0,
                identity_store=store,
            )
            await issuer.start()
            try:
                denied_client = _MfaClient(
                    "wrong",
                    pyotp.TOTP("JBSWY3DPEHPK3PXP").now(),
                )
                with pytest.raises(
                    (asyncssh.PermissionDenied, asyncssh.ConnectionLost)
                ):
                    async with asyncssh.connect(
                        "127.0.0.1",
                        port=issuer.port,
                        username="alice",
                        known_hosts=None,
                        client_factory=lambda: denied_client,
                        kbdint_auth=True,
                    ):
                        pass
                assert denied_client.prompts == ("Password:", "2FA:")

                accepted_client = _MfaClient(
                    "password",
                    pyotp.TOTP("JBSWY3DPEHPK3PXP").now(),
                )
                async with asyncssh.connect(
                    "127.0.0.1",
                    port=issuer.port,
                    username="alice",
                    known_hosts=None,
                    client_factory=lambda: accepted_client,
                    kbdint_auth=True,
                ):
                    pass
            finally:
                await issuer.close()

        asyncio.run(exercise())
    finally:
        database.close()


def test_authentication_denial_does_not_echo_factor_or_store_details(
    tmp_path: Path,
) -> None:
    """Denied MFA responses expose no password, TOTP, or backend detail."""
    database = StateDatabase.open(tmp_path / "state.sqlite3")
    try:
        store = SqliteIdentityStore(database)
        store.create_user("alice", "password", "JBSWY3DPEHPK3PXP")
        password = "DENIAL_PASSWORD_MARKER"
        code = "DENIAL_TOTP_MARKER"

        async def exercise() -> None:
            issuer = TracerIssuer(
                bind="127.0.0.1",
                port=0,
                identity_store=store,
            )
            await issuer.start()
            try:
                client = _MfaClient(password, code)
                with pytest.raises(
                    (asyncssh.PermissionDenied, asyncssh.ConnectionLost),
                ) as denied:
                    async with asyncssh.connect(
                        "127.0.0.1",
                        port=issuer.port,
                        username="alice",
                        known_hosts=None,
                        client_factory=lambda: client,
                        kbdint_auth=True,
                    ):
                        pass
                assert password not in str(denied.value)
                assert code not in str(denied.value)
                assert "identity data" not in str(denied.value)
            finally:
                await issuer.close()

        asyncio.run(exercise())
    finally:
        database.close()


@pytest.mark.parametrize("offset", [-60, -30, 0, 30, 60])
def test_totp_window_is_enforced_through_real_ssh(
    offset: int,
    tmp_path: Path,
) -> None:
    """Only previous, current, and next 30-second steps authenticate."""
    base_time = 1_700_000_010
    database = StateDatabase.open(tmp_path / f"totp-{offset}.sqlite3")
    try:
        store = SqliteIdentityStore(database)
        store.create_user("alice", "password", "JBSWY3DPEHPK3PXP")

        async def exercise() -> None:
            issuer = TracerIssuer(
                bind="127.0.0.1",
                port=0,
                identity_store=store,
                clock=lambda: base_time,
            )
            await issuer.start()
            try:
                client = _MfaClient(
                    "password",
                    pyotp.TOTP("JBSWY3DPEHPK3PXP").at(base_time + offset),
                )
                connection = asyncssh.connect(
                    "127.0.0.1",
                    port=issuer.port,
                    username="alice",
                    known_hosts=None,
                    client_factory=lambda: client,
                    kbdint_auth=True,
                )
                if offset in {-30, 0, 30}:
                    async with connection:
                        pass
                else:
                    with pytest.raises(
                        (asyncssh.PermissionDenied, asyncssh.ConnectionLost)
                    ):
                        async with connection:
                            pass
            finally:
                await issuer.close()

        asyncio.run(exercise())
    finally:
        database.close()
