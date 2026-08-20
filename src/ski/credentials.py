"""In-memory disposable credentials for the tracer issuer."""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass

import asyncssh

TRACER_CERTIFICATE_LIFETIME = 60 * 60


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
