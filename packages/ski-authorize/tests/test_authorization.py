"""Public offline authorization decisions."""

from __future__ import annotations

from dataclasses import replace

import pytest

from ski_authorize.authorization import AuthorizationDenied, authorize_certificate
from ski_authorize.certificate import CertificateAttributes
from ski_authorize.policy import HostPolicy

FINGERPRINT = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def test_valid_certificate_returns_the_first_permitted_group() -> None:
    """A certificate-bound self-login returns one local allowed principal."""
    policy = HostPolicy(
        trusted_ca_fingerprint=FINGERPRINT,
        allowed_groups=("group:database-oncall", "group:platform-ops"),
        allow_self_login_only=True,
    )
    certificate = CertificateAttributes(
        algorithm="ssh-ed25519-cert-v01@openssh.com",
        ca_algorithm="ssh-ed25519",
        ca_fingerprint=FINGERPRINT,
        key_id="alice",
        principals=("alice", "group:platform-ops", "group:database-oncall"),
        serial=7,
        valid_after=1_700_000_000,
        valid_before=1_700_100_000,
    )

    principal = authorize_certificate(
        policy,
        certificate,
        supplied_ca_fingerprint=FINGERPRINT,
        target_user="alice",
    )

    assert principal == "group:database-oncall"


def _policy(*groups: str) -> HostPolicy:
    return HostPolicy(
        trusted_ca_fingerprint=FINGERPRINT,
        allowed_groups=groups,
        allow_self_login_only=True,
    )


def _certificate(*, principals: tuple[str, ...] | None = None) -> CertificateAttributes:
    return CertificateAttributes(
        algorithm="ssh-ed25519-cert-v01@openssh.com",
        ca_algorithm="ssh-ed25519",
        ca_fingerprint=FINGERPRINT,
        key_id="alice",
        principals=("alice", "group:platform-ops")
        if principals is None
        else principals,
        serial=7,
        valid_after=1_700_000_000,
        valid_before=1_700_100_000,
    )


@pytest.mark.parametrize(
    ("policy", "certificate", "supplied", "target"),
    [
        (
            _policy("group:platform-ops"),
            _certificate(),
            "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            "alice",
        ),
        (_policy("group:platform-ops"), _certificate(), FINGERPRINT, "bob"),
        (
            _policy("group:platform-ops"),
            _certificate(principals=("group:platform-ops",)),
            FINGERPRINT,
            "alice",
        ),
        (
            _policy("group:platform-ops"),
            _certificate(principals=("alice",)),
            FINGERPRINT,
            "alice",
        ),
        (
            _policy("group:platform-ops"),
            _certificate(
                principals=("alice", "group:platform-ops", "group:platform-ops")
            ),
            FINGERPRINT,
            "alice",
        ),
        (
            _policy("group:platform-ops"),
            _certificate(principals=("alice", "not-a-group")),
            FINGERPRINT,
            "alice",
        ),
        (
            _policy("group:platform-ops"),
            _certificate(principals=("alice", "alice")),
            FINGERPRINT,
            "alice",
        ),
        (_policy("group:other"), _certificate(), FINGERPRINT, "alice"),
        (_policy(), _certificate(), FINGERPRINT, "alice"),
    ],
)
def test_invalid_bindings_are_denied(
    policy: HostPolicy,
    certificate: CertificateAttributes,
    supplied: str,
    target: str,
) -> None:
    with pytest.raises(AuthorizationDenied):
        authorize_certificate(
            policy,
            certificate,
            supplied_ca_fingerprint=supplied,
            target_user=target,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("key_id", "Alice"),
        ("key_id", "alice@example"),
        ("principals", ("alice", "group:Platform-Ops")),
    ],
)
def test_noncanonical_identity_or_group_values_are_denied(
    field: str, value: object
) -> None:
    certificate = replace(_certificate(), **{field: value})
    with pytest.raises(AuthorizationDenied):
        authorize_certificate(
            _policy("group:platform-ops"),
            certificate,
            supplied_ca_fingerprint=FINGERPRINT,
            target_user="alice",
        )
