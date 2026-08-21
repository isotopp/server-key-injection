"""Shared test configuration helpers."""

from __future__ import annotations

import asyncio
import os
import re
import sqlite3
from collections.abc import AsyncIterator, Callable, Iterator, Sequence
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from pathlib import Path

import asyncssh

from ski.ca import CAFileWriter
from ski.identities import SqliteIdentityStore, UserRecord
from ski.journal import MemoryEventSink
from ski.runtime import ServiceRuntime
from ski.state import StateDatabase


@contextmanager
def raw_sqlite_connection(path: Path) -> Iterator[sqlite3.Connection]:
    """Open a raw SQLite connection for deliberate corruption setup in tests."""
    connection = sqlite3.connect(path)
    try:
        yield connection
    finally:
        connection.close()


class MfaClient(asyncssh.SSHClient):
    def __init__(self, password: str, code: str) -> None:
        self.password = password
        self.code = code
        self.prompts: tuple[str, ...] = ()

    def kbdint_auth_requested(self) -> str:
        return ""

    def kbdint_challenge_received(
        self,
        name: str,
        instructions: str,
        lang: str,
        prompts: Sequence[tuple[str, bool]],
    ) -> list[str]:
        self.prompts = tuple(prompt for prompt, _ in prompts)
        return [self.password, self.code]


def mfa_client_factory(password: str, code: str) -> Callable[[], MfaClient]:
    """Return an AsyncSSH client factory answering the two MFA prompts."""
    return lambda: MfaClient(password, code)


@dataclass(frozen=True, slots=True)
class EnrolledRuntime:
    """Resources owned by one enrolled issuer integration scenario."""

    runtime: ServiceRuntime
    user: UserRecord
    database: Path
    agent_environment: dict[str, str]
    event_sink: MemoryEventSink


@asynccontextmanager
async def enrolled_runtime(
    tmp_path: Path,
    *,
    username: str = "alice",
    password: str = "password",
    totp_secret: str = "JBSWY3DPEHPK3PXP",
    groups: Sequence[str] = (),
) -> AsyncIterator[EnrolledRuntime]:
    """Run a configured issuer with one enrolled demo user and agent."""
    database = tmp_path / "state.sqlite3"
    state = StateDatabase.open(database)
    try:
        store = SqliteIdentityStore(state)
        user = store.create_user(username, password, totp_secret)
        for group in groups:
            store.create_group(group)
            store.add_membership(group, username)
        user = store.get_user(username)
    finally:
        state.close()

    event_sink = MemoryEventSink()
    runtime = ServiceRuntime(
        bind="127.0.0.1",
        port=0,
        exported_environment=runtime_environment(tmp_path, database),
        event_sink=event_sink,
    )
    await runtime.start()
    try:
        async with ssh_agent() as agent_environment:
            yield EnrolledRuntime(
                runtime, user, database, agent_environment, event_sink
            )
    finally:
        await runtime.close()


@asynccontextmanager
async def ssh_agent() -> AsyncIterator[dict[str, str]]:
    """Run an isolated real ``ssh-agent`` for one integration scenario."""
    process = await asyncio.create_subprocess_exec(
        "ssh-agent",
        "-s",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        raise RuntimeError(stderr.decode())

    output = stdout.decode()
    socket_match = re.search(r"SSH_AUTH_SOCK=([^;]+);", output)
    pid_match = re.search(r"SSH_AGENT_PID=([^;]+);", output)
    if socket_match is None or pid_match is None:
        raise RuntimeError("ssh-agent did not report its environment")
    environment = {
        "SSH_AUTH_SOCK": socket_match.group(1),
        "SSH_AGENT_PID": pid_match.group(1),
    }
    try:
        yield environment
    finally:
        stop_process = await asyncio.create_subprocess_exec(
            "ssh-agent",
            "-k",
            env={**os.environ, **environment},
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await stop_process.communicate()
        Path(environment["SSH_AUTH_SOCK"]).unlink(missing_ok=True)


def runtime_environment(tmp_path: Path, database: Path) -> dict[str, str]:
    """Return a complete runtime environment with a test persistent CA."""
    environment = {
        "SKI_CA_DATABASE": str(database),
        "SKI_CA_PRIVATE_KEY": str(tmp_path / "user_ca"),
        "SKI_CA_PUBLIC_KEY": str(tmp_path / "user_ca.pub"),
        "SKI_CA_KRL": str(tmp_path / "revoked.krl"),
        "ORDINARY_CERT_EXTENSIONS": "pty",
    }
    state = StateDatabase.open(database, owner=True)
    try:
        if state.get_active_ca() is None:
            material = CAFileWriter().install(
                private_path=tmp_path / "user_ca",
                public_path=tmp_path / "user_ca.pub",
                krl_path=tmp_path / "revoked.krl",
            )
            state.initialize_active_ca(
                public_key=material.public_bytes,
                fingerprint=material.fingerprint,
                private_key_path=tmp_path / "user_ca",
                request_id="test-ca-init",
            )
    finally:
        state.close()
    return environment
