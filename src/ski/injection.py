"""Injection of ordinary issuer credentials into a forwarded agent."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, NoReturn

import asyncssh

from ski.ca import ValidatedActiveCA
from ski.credentials import (
    FailureEventOutcome,
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

    async def remove_credential(
        self,
        credential: OrdinaryIdentity,
    ) -> AgentCleanupOutcome:
        """Remove both agent entries and report partial cleanup explicitly."""
        removed = 0
        failures: list[str] = []
        for public_data in (
            credential.public_key.public_data,
            credential.certificate.public_data,
        ):
            try:
                added = await self._client.get_keys([public_data])
                if added:
                    await self._client.remove_keys(list(added))
                    removed += len(added)
            except Exception as exc:
                failures.append(type(exc).__name__)
        return AgentCleanupOutcome(removed, tuple(failures))

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


@dataclass(frozen=True, slots=True)
class AgentCleanupOutcome:
    """Internal result of removing one generated credential from an agent."""

    removed: int
    error_codes: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        """Return whether every attempted cleanup operation succeeded."""
        return not self.error_codes


@dataclass(frozen=True, slots=True)
class IssuanceFailureOutcome:
    """Internal evidence collected for one failed issuance attempt."""

    cause_code: str
    cleanup: AgentCleanupOutcome | None
    audit: FailureEventOutcome


class IssuanceWorkflowError(StateError):
    """Safe internal failure carrying cleanup and audit outcomes."""

    def __init__(self, outcome: IssuanceFailureOutcome) -> None:
        super().__init__("ordinary certificate request failed")
        self.outcome = outcome


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
                            cleanup = await agent.remove_credential(credential)
                            if not cleanup.complete:
                                raise StateError("credential cleanup failed")
                            continue
                        return OrdinaryInjectionResult(
                            credential=credential,
                            record=record,
                            groups=identity.groups,
                        )
                except Exception as exc:
                    if credential is not None:
                        cleanup_outcome = await agent.remove_credential(credential)
                    else:
                        cleanup_outcome = None
                    self._raise_workflow_failure(
                        exc, cleanup_outcome, identity, request_id
                    )
        except IssuanceWorkflowError:
            raise
        except Exception as exc:
            self._raise_workflow_failure(exc, None, identity, request_id)
        self._raise_workflow_failure(
            StateError("certificate serial allocation failed"),
            None,
            identity,
            request_id,
        )

    def _raise_workflow_failure(
        self,
        cause: Exception,
        cleanup: AgentCleanupOutcome | None,
        identity: IdentitySnapshot,
        request_id: str,
    ) -> NoReturn:
        """Raise one safe failure carrying explicit cleanup and audit evidence."""
        try:
            audit = self._issuance.record_failure(identity, request_id)
        except Exception as exc:
            audit = FailureEventOutcome(False, type(exc).__name__)
        if not isinstance(audit, FailureEventOutcome):
            audit = FailureEventOutcome(False, "invalid_outcome")
        raise IssuanceWorkflowError(
            IssuanceFailureOutcome(type(cause).__name__, cleanup, audit),
        ) from cause
