"""In-memory disposable credentials for the tracer issuer."""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass

import asyncssh

from ski.ca import ValidatedActiveCA
from ski.identities import IdentitySnapshot
from ski.policy import PolicyValidationError, build_principals
from ski.state import (
    ORDINARY_CERTIFICATE_LIFETIME,
    CertificateRecord,
    StateDatabase,
    StateError,
)

TRACER_CERTIFICATE_LIFETIME = 60 * 60
ORDINARY_EXTENSION_FLAGS = {
    "pty": "permit_pty",
    "agent-forwarding": "permit_agent_forwarding",
    "port-forwarding": "permit_port_forwarding",
    "x11-forwarding": "permit_x11_forwarding",
    "user-rc": "permit_user_rc",
}


@dataclass(frozen=True, slots=True)
class TracerIdentity:
    """An ephemeral private key and its matching user certificate."""

    private_key: asyncssh.SSHKey
    certificate: asyncssh.SSHCertificate
    key_id: str
    comment: str
    valid_after: int
    valid_before: int

    @property
    def public_key(self) -> asyncssh.SSHKey:
        """Return the public half of the ephemeral user key."""
        return self.private_key.convert_to_public()

    @property
    def agent_keypair(self) -> tuple[asyncssh.SSHKey, asyncssh.SSHCertificate]:
        """Return the key and certificate in AsyncSSH agent input form."""
        return self.private_key, self.certificate


@dataclass(frozen=True, slots=True)
class OrdinaryIdentity:
    """One fresh ordinary user keypair and its persistent-CA certificate."""

    private_key: asyncssh.SSHKey
    certificate: asyncssh.SSHCertificate
    key_id: str
    principals: tuple[str, ...]
    serial: int
    valid_after: int
    valid_before: int
    comment: str

    @property
    def public_key(self) -> asyncssh.SSHKey:
        """Return the public half of the generated user key."""
        return self.private_key.convert_to_public()

    @property
    def agent_keypair(self) -> tuple[asyncssh.SSHKey, asyncssh.SSHCertificate]:
        """Return the key and certificate in AsyncSSH agent input form."""
        return self.private_key, self.certificate


class OrdinaryCertificateFactory:
    """Construct fixed-lifetime Ed25519 certificates from a validated CA."""

    def __init__(
        self,
        active_ca: ValidatedActiveCA,
        *,
        extensions: tuple[str, ...],
        clock: Callable[[], float] = time.time,
        serial_allocator: Callable[[], int] | None = None,
    ) -> None:
        unknown = set(extensions) - set(ORDINARY_EXTENSION_FLAGS)
        if unknown or len(set(extensions)) != len(extensions):
            raise StateError("ordinary certificate extensions are malformed")
        self._active_ca = active_ca
        self._extensions = frozenset(extensions)
        self._clock = clock
        self._serial_allocator = (
            (lambda: secrets.randbits(64))
            if serial_allocator is None
            else serial_allocator
        )

    def issue(self, identity: IdentitySnapshot) -> OrdinaryIdentity:
        """Generate and sign one fresh certificate for an immutable identity."""
        try:
            principals = build_principals(identity.username, identity.groups)
        except PolicyValidationError as exc:
            raise StateError("ordinary identity principals are malformed") from exc
        serial = self._serial_allocator()
        if not isinstance(serial, int) or not 0 <= serial < 2**64:
            raise StateError("certificate serial is malformed")
        valid_after = int(self._clock())
        valid_before = valid_after + ORDINARY_CERTIFICATE_LIFETIME
        comment = (
            f"ski:{identity.username}:{self._active_ca.record.fingerprint}:{serial}"
        )
        private_key = asyncssh.generate_private_key(
            "ssh-ed25519",
            comment=comment,
        )
        flags = {
            flag: extension in self._extensions
            for extension, flag in ORDINARY_EXTENSION_FLAGS.items()
        }
        certificate = self._active_ca.private_key.generate_user_certificate(
            private_key,
            identity.username,
            serial=serial,
            principals=principals,
            valid_after=valid_after,
            valid_before=valid_before,
            permit_x11_forwarding=flags["permit_x11_forwarding"],
            permit_agent_forwarding=flags["permit_agent_forwarding"],
            permit_port_forwarding=flags["permit_port_forwarding"],
            permit_pty=flags["permit_pty"],
            permit_user_rc=flags["permit_user_rc"],
            touch_required=True,
            comment=comment,
        )
        return OrdinaryIdentity(
            private_key=private_key,
            certificate=certificate,
            key_id=identity.username,
            principals=principals,
            serial=serial,
            valid_after=valid_after,
            valid_before=valid_before,
            comment=comment,
        )


class OrdinaryIssuanceService:
    """Build ordinary certificates and commit safe issuance evidence."""

    def __init__(
        self,
        database: StateDatabase,
        active_ca: ValidatedActiveCA,
        *,
        extensions: tuple[str, ...],
        clock: Callable[[], float] = time.time,
        serial_allocator: Callable[[], int] | None = None,
    ) -> None:
        self._database = database
        self._active_ca = active_ca
        self._factory = OrdinaryCertificateFactory(
            active_ca,
            extensions=extensions,
            clock=clock,
            serial_allocator=serial_allocator,
        )

    @property
    def active_ca(self) -> ValidatedActiveCA:
        """Return the validated CA used for signing."""
        return self._active_ca

    def issue(
        self,
        identity: IdentitySnapshot,
        *,
        request_id: str,
    ) -> tuple[OrdinaryIdentity, CertificateRecord]:
        """Issue one certificate and atomically record its successful outcome."""
        for _ in range(5):
            credential = self.prepare(identity)
            try:
                record = self.commit(credential, request_id=request_id)
            except StateError as exc:
                if "serial is already recorded" in str(exc):
                    continue
                self.record_failure(identity, request_id)
                raise
            return credential, record
        self.record_failure(identity, request_id)
        raise StateError("certificate serial allocation failed")

    def prepare(self, identity: IdentitySnapshot) -> OrdinaryIdentity:
        """Generate a credential without durable state or agent side effects."""
        return self._factory.issue(identity)

    def commit(
        self,
        credential: OrdinaryIdentity,
        *,
        request_id: str,
    ) -> CertificateRecord:
        """Persist one prepared credential and its successful event atomically."""
        return self._database.record_certificate_with_event(
            ca_id=self._active_ca.record.ca_id,
            serial=credential.serial,
            identity=credential.key_id,
            public_key_fingerprint=credential.public_key.get_fingerprint(),
            principals=credential.principals,
            valid_after=credential.valid_after,
            valid_before=credential.valid_before,
            request_id=request_id,
        )

    def record_failure(self, identity: IdentitySnapshot, request_id: str) -> None:
        """Append a safe failed-operation event when durable state permits it."""
        try:
            self._database.record_event(
                kind="certificate_failed",
                decision="deny",
                request_id=request_id,
                identity=identity.username,
                ca_id=self._active_ca.record.ca_id,
            )
        except Exception:
            pass


class DisposableCertificateFactory:
    """Issue short-lived identities signed by a process-local test CA."""

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._ca_key = asyncssh.generate_private_key("ssh-ed25519")

    def issue(self) -> TracerIdentity:
        """Generate one fresh, one-hour dummy user certificate."""
        key_id = f"test-{secrets.token_hex(16)}"
        private_key = asyncssh.generate_private_key("ssh-ed25519", comment=key_id)
        valid_after = int(self._clock())
        valid_before = valid_after + TRACER_CERTIFICATE_LIFETIME
        certificate = self._ca_key.generate_user_certificate(
            private_key,
            key_id,
            principals=["dummy"],
            valid_after=valid_after,
            valid_before=valid_before,
            permit_x11_forwarding=False,
            permit_agent_forwarding=False,
            permit_port_forwarding=False,
            permit_pty=False,
            permit_user_rc=False,
            touch_required=False,
            comment=key_id,
        )
        return TracerIdentity(
            private_key=private_key,
            certificate=certificate,
            key_id=key_id,
            comment=key_id,
            valid_after=valid_after,
            valid_before=valid_before,
        )
