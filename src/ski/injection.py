"""Injection of disposable tracer credentials into a forwarded agent."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

import asyncssh

from ski.credentials import (
    TRACER_CERTIFICATE_LIFETIME,
    DisposableCertificateFactory,
    OrdinaryIdentity,
    OrdinaryIssuanceService,
)
from ski.identities import IdentitySnapshot
from ski.state import CertificateRecord, StateError


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


class OrdinaryAgentInjector:
    """Issue one ordinary credential and replace only its owned agent entry."""

    def __init__(
        self,
        issuance: OrdinaryIssuanceService,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._issuance = issuance
        self._active_ca = issuance.active_ca
        self._clock = clock

    async def handle(
        self,
        connection: asyncssh.SSHServerConnection,
        identity: IdentitySnapshot,
        *,
        request_id: str,
    ) -> OrdinaryInjectionResult:
        """Replace one provably owned credential after durable issuance."""
        try:
            async with asyncssh.connect_agent(connection) as agent:
                keys = await agent.get_keys()
                owned = [pair for pair in keys if self._is_owned(pair, identity)]
                removed_owned = False
                for _ in range(5):
                    credential = self._issuance.prepare(identity)
                    lifetime = max(1, credential.valid_before - int(self._clock()))
                    if owned and not removed_owned:
                        await agent.remove_keys(owned)
                        removed_owned = True
                    await agent.add_keys([credential.agent_keypair], lifetime=lifetime)
                    try:
                        record = self._issuance.commit(
                            credential,
                            request_id=request_id,
                        )
                    except Exception as exc:
                        await self._remove_prepared(agent, credential)
                        if isinstance(
                            exc, StateError
                        ) and "serial is already recorded" in str(
                            exc,
                        ):
                            continue
                        raise
                    return OrdinaryInjectionResult(
                        credential=credential,
                        record=record,
                        groups=identity.groups,
                    )
        except Exception:
            self._issuance.record_failure(identity, request_id)
            raise
        self._issuance.record_failure(identity, request_id)
        raise StateError("certificate serial allocation failed")

    @staticmethod
    async def _remove_prepared(
        agent: asyncssh.SSHAgentClient,
        credential: OrdinaryIdentity,
    ) -> None:
        """Remove a newly added pair without touching unrelated identities."""
        try:
            added = await agent.get_keys([credential.public_key.public_data])
            if added:
                await agent.remove_keys(added)
        except Exception:
            pass

    def _is_owned(self, pair: asyncssh.SSHKeyPair, identity: IdentitySnapshot) -> bool:
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
        principal_values = tuple(principals or ())
        if (
            not isinstance(serial, int)
            or not isinstance(key_id, str)
            or key_id != username
            or signing_key is None
            or signing_key.get_fingerprint() != self._active_ca.record.fingerprint
            or not principal_values
            or principal_values[0] != username
            or any(
                not isinstance(principal, str) or not principal.startswith("group:")
                for principal in principal_values[1:]
            )
        ):
            return False
        marker = f"ski:{username}:{self._active_ca.record.fingerprint}:{serial}"
        return comment == marker
