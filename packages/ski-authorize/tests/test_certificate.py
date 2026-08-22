"""Public OpenSSH certificate parsing behaviour."""

from __future__ import annotations

import base64

import asyncssh
import pytest

from ski_authorize.certificate import parse_certificate


def _export_certificate(*, host: bool = False) -> tuple[str, str]:
    """Create one local OpenSSH certificate fixture without issuer imports."""
    ca_key = asyncssh.generate_private_key("ssh-ed25519")
    user_key = asyncssh.generate_private_key("ssh-ed25519")
    if host:
        certificate = ca_key.generate_host_certificate(
            user_key,
            "host",
            serial=7,
            principals=("host",),
            valid_after=1_700_000_000,
            valid_before=1_700_100_000,
        )
    else:
        certificate = ca_key.generate_user_certificate(
            user_key,
            "alice",
            serial=7,
            principals=("alice", "group:platform-ops"),
            valid_after=1_700_000_000,
            valid_before=1_700_100_000,
        )
    exported = certificate.export_certificate().decode("ascii").split()
    return exported[0], exported[1]


def test_ed25519_user_certificate_exposes_safe_decision_attributes() -> None:
    """A valid type-plus-base64 certificate becomes a safe attribute value."""
    ca_key = asyncssh.generate_private_key("ssh-ed25519")
    user_key = asyncssh.generate_private_key("ssh-ed25519")
    certificate = ca_key.generate_user_certificate(
        user_key,
        "alice",
        serial=7,
        principals=("alice", "group:platform-ops"),
        valid_after=1_700_000_000,
        valid_before=1_700_100_000,
    )
    exported = certificate.export_certificate().decode("ascii").split()

    attributes = parse_certificate(
        exported[0],
        base64.b64encode(base64.b64decode(exported[1])).decode("ascii"),
        clock=lambda: 1_700_050_000,
    )

    assert attributes.algorithm == "ssh-ed25519-cert-v01@openssh.com"
    assert attributes.key_id == "alice"
    assert attributes.principals == ("alice", "group:platform-ops")
    assert attributes.serial == 7
    assert attributes.valid_after == 1_700_000_000
    assert attributes.valid_before == 1_700_100_000
    assert attributes.ca_fingerprint == ca_key.get_fingerprint()


@pytest.mark.parametrize(
    ("certificate_type", "certificate_base64"),
    [
        ("ssh-ed25519-cert-v01@openssh.com", "%%%"),
        ("ssh-ed25519-cert-v01@openssh.com", "bm90LWEtY2VydGlmaWNhdGU="),
        ("ssh-rsa-cert-v01@openssh.com", "bm90LWEtY2VydGlmaWNhdGU="),
    ],
)
def test_malformed_or_unsupported_certificate_input_is_rejected(
    certificate_type: str,
    certificate_base64: str,
) -> None:
    """Malformed bodies, mismatched types, and unsupported algorithms deny."""
    with pytest.raises(ValueError):
        parse_certificate(certificate_type, certificate_base64)


def test_host_certificate_is_rejected() -> None:
    """The helper accepts user certificates only."""
    certificate_type, certificate_base64 = _export_certificate(host=True)

    with pytest.raises(ValueError):
        parse_certificate(
            certificate_type,
            certificate_base64,
            clock=lambda: 1_700_050_000,
        )


def test_expired_and_not_yet_valid_certificates_are_rejected() -> None:
    """Certificate validity is checked using the injected current time."""
    ca_key = asyncssh.generate_private_key("ssh-ed25519")
    user_key = asyncssh.generate_private_key("ssh-ed25519")
    certificate = ca_key.generate_user_certificate(
        user_key,
        "alice",
        valid_after=1_700_000_000,
        valid_before=1_700_100_000,
    )
    certificate_type, certificate_base64 = (
        certificate.export_certificate().decode("ascii").split()
    )

    with pytest.raises(ValueError):
        parse_certificate(
            certificate_type, certificate_base64, clock=lambda: 1_699_999_999
        )
    with pytest.raises(ValueError):
        parse_certificate(
            certificate_type, certificate_base64, clock=lambda: 1_700_100_000
        )
