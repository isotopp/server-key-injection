"""Behavioural tests for the test issuer runtime."""

from __future__ import annotations

import asyncio

import asyncssh
import pytest

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


def test_tracer_rejects_a_session_without_agent_forwarding() -> None:
    """A tracer session explains that agent forwarding is required."""

    async def exercise() -> None:
        requests = 0

        async def record_request(_connection: asyncssh.SSHServerConnection) -> None:
            nonlocal requests
            requests += 1

        issuer = TracerIssuer(
            bind="127.0.0.1",
            port=0,
            request_handler=record_request,
        )
        await issuer.start()
        try:
            async with asyncssh.connect(
                "127.0.0.1",
                port=issuer.port,
                username="test-user",
                known_hosts=None,
                agent_forwarding=False,
            ) as connection:
                process = await connection.create_process(
                    command=None,
                    request_pty=False,
                )
                _, stderr = await process.communicate()

                assert process.exit_status == 1
                assert "Agent forwarding is required" in stderr
            assert requests == 0
        finally:
            await issuer.close()

    asyncio.run(exercise())


def test_tracer_accepts_a_forwarding_enabled_session() -> None:
    """A forwarding-enabled session reaches the tracer request boundary."""

    async def exercise() -> None:
        requests = 0

        async def record_request(_connection: asyncssh.SSHServerConnection) -> None:
            nonlocal requests
            requests += 1

        issuer = TracerIssuer(
            bind="127.0.0.1",
            port=0,
            request_handler=record_request,
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
                stdout, stderr = await process.communicate()

                assert process.exit_status == 0
                assert stdout == "Tracer request accepted.\n"
                assert stderr == ""

            assert requests == 1
        finally:
            await issuer.close()

    asyncio.run(exercise())


def test_tracer_rejects_exec_requests() -> None:
    """The test issuer does not expose arbitrary command execution."""

    async def exercise() -> None:
        issuer = TracerIssuer(bind="127.0.0.1", port=0)
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


def test_tracer_rejects_direct_tcp_forwarding() -> None:
    """The test issuer does not expose direct TCP forwarding."""

    async def exercise() -> None:
        issuer = TracerIssuer(bind="127.0.0.1", port=0)
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
