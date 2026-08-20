"""Injection of disposable tracer credentials into a forwarded agent."""

from __future__ import annotations

import asyncssh

from ski.credentials import (
    TRACER_CERTIFICATE_LIFETIME,
    DisposableCertificateFactory,
)


class TracerAgentInjector:
    """Generate one tracer identity and add it to the forwarded agent."""

    def __init__(
        self,
        factory: DisposableCertificateFactory | None = None,
    ) -> None:
        self._factory = factory or DisposableCertificateFactory()

    async def handle(self, connection: asyncssh.SSHServerConnection) -> str:
        """Inject a fresh identity and return its safe key identifier."""
        identity = self._factory.issue()
        async with asyncssh.connect_agent(connection) as agent:
            await agent.add_keys(
                [identity.agent_keypair],
                lifetime=TRACER_CERTIFICATE_LIFETIME,
            )
        return identity.key_id
