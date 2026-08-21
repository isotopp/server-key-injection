"""Shared test configuration helpers."""

from __future__ import annotations

import asyncio
import os
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from ski.ca import CAFileWriter
from ski.state import StateDatabase


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
