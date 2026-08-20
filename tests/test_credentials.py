"""Behavioural tests for disposable tracer credentials."""

from __future__ import annotations

import asyncssh

from ski.credentials import DisposableCertificateFactory


def test_factory_issues_a_real_in_memory_user_certificate() -> None:
    """The factory returns a usable OpenSSH user certificate identity."""
    identity = DisposableCertificateFactory().issue()

    assert isinstance(identity.certificate, asyncssh.SSHCertificate)
    assert identity.certificate.key.public_data == identity.public_key.public_data
    assert identity.certificate.export_certificate().startswith(
        b"ssh-ed25519-cert-v01@openssh.com "
    )
    assert identity.key_id.startswith("test-")


def test_factory_issues_distinct_identities_for_each_request() -> None:
    """Each request receives a new user key and certificate identity."""
    factory = DisposableCertificateFactory()

    first = factory.issue()
    second = factory.issue()

    assert first.key_id != second.key_id
    assert first.public_key.public_data != second.public_key.public_data


def test_factory_uses_test_marker_and_one_hour_validity() -> None:
    """Tracer metadata has a fixed one-hour validity interval."""
    identity = DisposableCertificateFactory(clock=lambda: 1_700_000_000.9).issue()

    assert identity.key_id.startswith("test-")
    assert identity.comment == identity.key_id
    assert identity.certificate.get_comment() == identity.comment
    assert identity.valid_after == 1_700_000_000
    assert identity.valid_before == 1_700_000_000 + 3_600
