"""Behavioural tests for tracer agent injection."""

from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path

import asyncssh

from ski.injection import TracerAgentInjector
from ski.server import TracerIssuer
from support import ssh_agent


async def _start_test_agent() -> dict[str, str]:
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
    return {
        "SSH_AUTH_SOCK": socket_match.group(1),
        "SSH_AGENT_PID": pid_match.group(1),
    }


async def _stop_test_agent(environment: dict[str, str]) -> None:
    process = await asyncio.create_subprocess_exec(
        "ssh-agent",
        "-k",
        env={**os.environ, **environment},
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await process.communicate()
    Path(environment["SSH_AUTH_SOCK"]).unlink(missing_ok=True)


def test_forwarded_agent_receives_the_dummy_identity() -> None:
    """A real forwarded agent receives the generated identity."""

    async def exercise() -> None:
        async with ssh_agent() as agent_environment:
            issuer = TracerIssuer(
                bind="127.0.0.1",
                port=0,
                request_handler=TracerAgentInjector().handle,
            )
            await issuer.start()
            try:
                async with asyncssh.connect(
                    "127.0.0.1",
                    port=issuer.port,
                    username="test-user",
                    known_hosts=None,
                    agent_path=agent_environment["SSH_AUTH_SOCK"],
                    agent_forwarding=True,
                ) as connection:
                    process = await connection.create_process(
                        command=None,
                        request_pty=False,
                    )
                    stdout, stderr = await process.communicate()

                    assert process.exit_status == 0
                    assert stdout.startswith("Key loaded: test-")
                    assert stderr == ""

                listed = await asyncio.create_subprocess_exec(
                    "ssh-add",
                    "-l",
                    env={**os.environ, **agent_environment},
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                listing, errors = await listed.communicate()
                assert listed.returncode == 0, errors.decode()
                assert b"test-" in listing
            finally:
                await issuer.close()

    asyncio.run(exercise())


def test_agent_transport_failure_does_not_report_success() -> None:
    """A failed forwarded-agent connection fails the tracer request closed."""

    async def exercise() -> None:
        issuer = TracerIssuer(
            bind="127.0.0.1",
            port=0,
            request_handler=TracerAgentInjector().handle,
        )
        await issuer.start()
        try:
            async with asyncssh.connect(
                "127.0.0.1",
                port=issuer.port,
                username="test-user",
                known_hosts=None,
                agent_path="/tmp/ski-test-agent-does-not-exist",
                agent_forwarding=True,
            ) as connection:
                process = await connection.create_process(
                    command=None,
                    request_pty=False,
                )
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=1,
                )

                assert process.exit_status == 1
                assert stdout == ""
                assert stderr == "Tracer request failed.\n"
        finally:
            await issuer.close()

    asyncio.run(exercise())


def test_repeated_tracer_sessions_create_distinct_identities() -> None:
    """Repeated successful requests add fresh tracer identities."""

    async def exercise() -> None:
        agent_environment = await _start_test_agent()
        agent_socket = Path(agent_environment["SSH_AUTH_SOCK"])
        issuer = TracerIssuer(
            bind="127.0.0.1",
            port=0,
            request_handler=TracerAgentInjector().handle,
        )
        await issuer.start()
        identities: list[str] = []
        try:
            for _ in range(2):
                async with asyncssh.connect(
                    "127.0.0.1",
                    port=issuer.port,
                    username="test-user",
                    known_hosts=None,
                    agent_path=agent_environment["SSH_AUTH_SOCK"],
                    agent_forwarding=True,
                ) as connection:
                    process = await connection.create_process(
                        command=None,
                        request_pty=False,
                    )
                    stdout, stderr = await process.communicate()
                    assert process.exit_status == 0
                    assert stderr == ""
                    identities.append(stdout.removeprefix("Key loaded: ").strip())

            assert len(identities) == 2
            assert len(set(identities)) == 2
            listed = await asyncio.create_subprocess_exec(
                "ssh-add",
                "-l",
                env={**os.environ, **agent_environment},
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            listing, errors = await listed.communicate()
            assert listed.returncode == 0, errors.decode()
            comments = [line.split()[-2].decode() for line in listing.splitlines()]
            assert len(comments) == 4  # one key and one certificate per request
            assert all(comments.count(identity) == 2 for identity in identities)
        finally:
            await issuer.close()
            await _stop_test_agent(agent_environment)

        assert not agent_socket.exists()

    asyncio.run(exercise())
