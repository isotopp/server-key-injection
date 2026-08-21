"""Injection of disposable tracer credentials into a forwarded agent."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import asyncssh

from ski.ca import ValidatedActiveCA
from ski.credentials import (
    TRACER_CERTIFICATE_LIFETIME,
    DisposableCertificateFactory,
    OrdinaryIdentity,
    OrdinaryIssuanceService,
)
from ski.identities import IdentitySnapshot
from ski.policy import PolicyValidationError, validate_principals
from ski.state import (
    CertificateRecord,
    DuplicateCertificateSerialError,
    StateError,
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


@dataclass(frozen=True, slots=True)
class OrdinaryInjectionResult:
    """Safe completion data for one ordinary agent injection."""

    credential: OrdinaryIdentity
    record: CertificateRecord
    groups: tuple[str, ...]


class AsyncSSHAgentAdapter:
    """Own AsyncSSH agent mechanics and issuer-credential ownership checks."""

    def __init__(
        self,
        client: asyncssh.SSHAgentClient,
        active_ca: ValidatedActiveCA,
    ) -> None:
        self._client = client
        self._active_ca = active_ca

    async def owned_keys(self, identity: IdentitySnapshot) -> list[asyncssh.SSHKeyPair]:
        """Return only existing agent entries proven to belong to this issuer."""
        keys = await self._client.get_keys()
        return [pair for pair in keys if self._is_owned(pair, identity)]

    async def remove_keys(self, keys: list[asyncssh.SSHKeyPair]) -> None:
        """Remove exactly the supplied, already-owned agent entries."""
        if keys:
            await self._client.remove_keys(keys)

    async def add_credential(
        self,
        credential: OrdinaryIdentity,
        *,
        lifetime: int,
    ) -> None:
        """Add one generated credential to the forwarded agent."""
        await self._client.add_keys(
            [credential.agent_keypair],
            lifetime=lifetime,
        )

    async def remove_credential(self, credential: OrdinaryIdentity) -> None:
        """Remove both agent entries associated with one generated credential."""
        try:
            for public_data in (
                credential.public_key.public_data,
                credential.certificate.public_data,
            ):
                added = await self._client.get_keys([public_data])
                if added:
                    await self._client.remove_keys(list(added))
        except Exception:
            pass

    def _is_owned(
        self,
        pair: asyncssh.SSHKeyPair,
        identity: IdentitySnapshot,
    ) -> bool:
        """Require marker, certificate identity, CA, serial, and principals."""
        username = identity.username
        try:
            certificate = getattr(pair, "cert", None)
            comment = pair.get_comment()
            if certificate is None or comment is None:
                return False
            serial = getattr(certificate, "_serial", None)
            key_id = getattr(certificate, "_key_id", None)
            signing_key = getattr(certificate, "signing_key", None)
            principals = getattr(certificate, "principals", None)
        except Exception:
            return False
        try:
            principal_values = validate_principals(tuple(principals or ()))
        except PolicyValidationError:
            return False
        if (
            not isinstance(serial, int)
            or not isinstance(key_id, str)
            or key_id != username
            or signing_key is None
            or signing_key.get_fingerprint() != self._active_ca.record.fingerprint
            or not principal_values
            or principal_values[0] != username
        ):
            return False
        marker = f"ski:{username}:{self._active_ca.record.fingerprint}:{serial}"
        return comment == marker


@asynccontextmanager
async def connected_agent(
    connection: asyncssh.SSHServerConnection,
    active_ca: ValidatedActiveCA,
) -> AsyncIterator[AsyncSSHAgentAdapter]:
    """Connect one adapter to the forwarded agent for a single request."""
    async with asyncssh.connect_agent(connection) as client:
        yield AsyncSSHAgentAdapter(client, active_ca)


class OrdinaryAgentInjector:
    """Issue one ordinary credential and replace only its owned agent entry."""

    def __init__(
        self,
        issuance: OrdinaryIssuanceService,
        *,
        clock: Callable[[], float] = time.time,
        agent_factory: Callable[..., Any] = connected_agent,
    ) -> None:
        self._issuance = issuance
        self._active_ca = issuance.active_ca
        self._clock = clock
        self._agent_factory = agent_factory

    async def handle(
        self,
        connection: asyncssh.SSHServerConnection,
        identity: IdentitySnapshot,
        *,
        request_id: str,
    ) -> OrdinaryInjectionResult:
        """Replace one provably owned credential after durable issuance."""
        try:
            async with self._agent_factory(connection, self._active_ca) as agent:
                owned = await agent.owned_keys(identity)
                removed_owned = False
                credential: OrdinaryIdentity | None = None
                try:
                    for _ in range(5):
                        credential = self._issuance.prepare(identity)
                        lifetime = max(
                            1,
                            credential.valid_before - int(self._clock()),
                        )
                        if owned and not removed_owned:
                            await agent.remove_keys(owned)
                            removed_owned = True
                        await agent.add_credential(credential, lifetime=lifetime)
                        try:
                            record = self._issuance.commit(
                                credential,
                                request_id=request_id,
                            )
                        except DuplicateCertificateSerialError:
                            await agent.remove_credential(credential)
                            continue
                        return OrdinaryInjectionResult(
                            credential=credential,
                            record=record,
                            groups=identity.groups,
                        )
                except Exception:
                    if credential is not None:
                        await agent.remove_credential(credential)
                    raise
        except Exception:
            self._issuance.record_failure(identity, request_id)
            raise
        self._issuance.record_failure(identity, request_id)
        raise StateError("certificate serial allocation failed")
