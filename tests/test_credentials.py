"""Behavioural tests for disposable tracer credentials."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import asyncssh
import pytest

from ski.ca import load_validated_active_ca
from ski.credentials import (
    DisposableCertificateFactory,
    OrdinaryCertificateFactory,
    OrdinaryIssuanceService,
)
from ski.identities import IdentitySnapshot
from ski.state import StateDatabase, StateError
from support import runtime_environment


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


def test_ordinary_factory_issues_persisted_ca_certificate_with_groups(
    tmp_path: Path,
) -> None:
    """Ordinary issuance has canonical identity, groups, serial, and 25 hours."""
    environment = runtime_environment(tmp_path, tmp_path / "state.sqlite3")
    database = StateDatabase.open(tmp_path / "state.sqlite3", owner=True)
    try:
        active_ca = load_validated_active_ca(
            database,
            private_path=Path(environment["SKI_CA_PRIVATE_KEY"]),
            public_path=Path(environment["SKI_CA_PUBLIC_KEY"]),
        )
        factory = OrdinaryCertificateFactory(
            active_ca,
            extensions=("pty", "agent-forwarding"),
            clock=lambda: 1_700_000_000.9,
            serial_allocator=lambda: 7,
        )
        identity = factory.issue(
            IdentitySnapshot(username="alice", groups=("platform-ops",)),
        )
        assert identity.key_id == "alice"
        assert identity.principals == ("alice", "group:platform-ops")
        assert identity.serial == 7
        assert identity.valid_after == 1_700_000_000
        assert identity.valid_before == 1_700_000_000 + 25 * 60 * 60
        certificate = cast(Any, identity.certificate)
        assert certificate.principals == list(identity.principals)
        assert certificate.signing_key.get_fingerprint() == (
            active_ca.record.fingerprint
        )
        assert certificate.options == {
            "permit-agent-forwarding": True,
            "permit-pty": True,
        }
    finally:
        database.close()


def test_ordinary_issuance_commits_certificate_and_event_without_private_key(
    tmp_path: Path,
) -> None:
    """Successful issuance returns safe state only after durable evidence exists."""
    environment = runtime_environment(tmp_path, tmp_path / "state.sqlite3")
    database = StateDatabase.open(tmp_path / "state.sqlite3", owner=True)
    try:
        active_ca = load_validated_active_ca(
            database,
            private_path=Path(environment["SKI_CA_PRIVATE_KEY"]),
            public_path=Path(environment["SKI_CA_PUBLIC_KEY"]),
        )
        service = OrdinaryIssuanceService(
            database,
            active_ca,
            extensions=("pty",),
            clock=lambda: 1_700_000_000,
            serial_allocator=lambda: 123,
        )
        credential, record = service.issue(
            IdentitySnapshot(username="alice", groups=()),
            request_id="request-ordinary-1",
        )
        assert record.serial == credential.serial == 123
        assert record.outcome == "success"
        assert [event.kind for event in database.list_events()] == [
            "ca_initialized",
            "certificate_issued",
        ]
        assert (
            credential.private_key.export_private_key()
            not in repr(
                database.list_certificates(),
            ).encode()
        )
    finally:
        database.close()


def test_ordinary_factory_denies_unlisted_forwarding_extensions(
    tmp_path: Path,
) -> None:
    """Port forwarding is absent unless explicitly selected by policy."""
    environment = runtime_environment(tmp_path, tmp_path / "state.sqlite3")
    database = StateDatabase.open(tmp_path / "state.sqlite3", owner=True)
    try:
        active_ca = load_validated_active_ca(
            database,
            private_path=Path(environment["SKI_CA_PRIVATE_KEY"]),
            public_path=Path(environment["SKI_CA_PUBLIC_KEY"]),
        )
        disabled = OrdinaryCertificateFactory(active_ca, extensions=("pty",)).issue(
            IdentitySnapshot(username="alice", groups=()),
        )
        enabled = OrdinaryCertificateFactory(
            active_ca,
            extensions=("pty", "port-forwarding"),
        ).issue(IdentitySnapshot(username="alice", groups=()))
        disabled_certificate = cast(Any, disabled.certificate)
        enabled_certificate = cast(Any, enabled.certificate)
        assert "permit-port-forwarding" not in disabled_certificate.options
        assert enabled_certificate.options["permit-port-forwarding"] is True
    finally:
        database.close()


def test_ordinary_issuance_retries_serial_collision_without_replacing_history(
    tmp_path: Path,
) -> None:
    """A duplicate serial is retried and never overwrites an earlier record."""
    environment = runtime_environment(tmp_path, tmp_path / "state.sqlite3")
    database = StateDatabase.open(tmp_path / "state.sqlite3", owner=True)
    try:
        active_ca = load_validated_active_ca(
            database,
            private_path=Path(environment["SKI_CA_PRIVATE_KEY"]),
            public_path=Path(environment["SKI_CA_PUBLIC_KEY"]),
        )
        first = OrdinaryIssuanceService(
            database,
            active_ca,
            extensions=("pty",),
            serial_allocator=lambda: 10,
        )
        first.issue(IdentitySnapshot(username="alice", groups=()), request_id="one")
        serials = iter((10, 11))
        second = OrdinaryIssuanceService(
            database,
            active_ca,
            extensions=("pty",),
            serial_allocator=lambda: next(serials),
        )
        credential, _ = second.issue(
            IdentitySnapshot(username="alice", groups=()),
            request_id="two",
        )
        assert credential.serial == 11
        assert [record.serial for record in database.list_certificates()] == [10, 11]
    finally:
        database.close()


def test_ordinary_issuance_does_not_retry_an_untyped_serial_message(
    tmp_path: Path,
) -> None:
    """Only DuplicateCertificateSerialError is retryable, not matching text."""
    environment = runtime_environment(tmp_path, tmp_path / "state.sqlite3")
    database = StateDatabase.open(tmp_path / "state.sqlite3", owner=True)
    try:
        active_ca = load_validated_active_ca(
            database,
            private_path=Path(environment["SKI_CA_PRIVATE_KEY"]),
            public_path=Path(environment["SKI_CA_PUBLIC_KEY"]),
        )

        class UnexpectedPersistence:
            commit_attempts = 0
            failure_events = 0

            def record_certificate_with_event(self, **kwargs: object) -> object:
                del kwargs
                self.commit_attempts += 1
                raise StateError("certificate serial is already recorded")

            def record_event(self, **kwargs: object) -> None:
                del kwargs
                self.failure_events += 1

        persistence = UnexpectedPersistence()
        service = OrdinaryIssuanceService(
            cast(StateDatabase, persistence),
            active_ca,
            extensions=("pty",),
            serial_allocator=lambda: 7,
        )

        with pytest.raises(StateError, match="certificate serial is already recorded"):
            service.issue(
                IdentitySnapshot(username="alice", groups=()),
                request_id="request-untyped-error",
            )

        assert persistence.commit_attempts == 1
        assert persistence.failure_events == 1
    finally:
        database.close()
