"""Characterization tests for security-relevant domain policy."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import asyncssh
import pytest

from ski.ca import load_validated_active_ca
from ski.credentials import OrdinaryCertificateFactory
from ski.identities import (
    IdentitySnapshot,
    IdentityValidationError,
    SqliteIdentityStore,
)
from ski.policy import PolicyValidationError, build_principals, validate_principals
from ski.state import DuplicateCertificateSerialError, StateDatabase, StateError
from support import runtime_environment


def test_identity_and_group_boundaries_accept_only_canonical_values(
    tmp_path: Path,
) -> None:
    """The public identity store preserves canonical grammar and stable groups."""
    database = StateDatabase.open(tmp_path / "state.sqlite3", owner=True)
    try:
        store = SqliteIdentityStore(database)
        for username in ("Alice", "a" * 33, "-bad", ""):
            with pytest.raises(IdentityValidationError):
                store.create_user(username, "password", "JBSWY3DPEHPK3PXP")

        store.create_user("alice", "password", "JBSWY3DPEHPK3PXP")
        store.create_group("platform-ops")
        store.add_membership("platform-ops", "alice")
        assert store.get_group_snapshot("alice").groups == ("platform-ops",)
    finally:
        database.close()


def test_certificate_policy_preserves_principals_extensions_and_25_hour_lifetime(
    tmp_path: Path,
) -> None:
    """Public ordinary issuance remains fixed-lifetime and least-privilege."""
    environment = runtime_environment(tmp_path, tmp_path / "state.sqlite3")
    database = StateDatabase.open(tmp_path / "state.sqlite3", owner=True)
    try:
        active_ca = load_validated_active_ca(
            database,
            private_path=Path(environment["SKI_CA_PRIVATE_KEY"]),
            public_path=Path(environment["SKI_CA_PUBLIC_KEY"]),
        )
        identity = OrdinaryCertificateFactory(
            active_ca,
            extensions=("pty", "agent-forwarding"),
            clock=lambda: 1_700_000_000.9,
            serial_allocator=lambda: 7,
        ).issue(IdentitySnapshot("alice", ("platform-ops",)))

        assert identity.principals == ("alice", "group:platform-ops")
        assert identity.valid_before - identity.valid_after == 25 * 60 * 60
        certificate = cast(Any, identity.certificate)
        assert isinstance(identity.certificate, asyncssh.SSHCertificate)
        assert certificate.options == {
            "permit-agent-forwarding": True,
            "permit-pty": True,
        }
    finally:
        database.close()


def test_persistence_rejects_duplicate_serials_and_wrong_lifetimes(
    tmp_path: Path,
) -> None:
    """The public recording boundary rejects conflicting certificate evidence."""
    database = StateDatabase.open(tmp_path / "state.sqlite3", owner=True)
    try:
        key = asyncssh.generate_private_key("ssh-ed25519")
        ca = database.register_active_ca(
            public_key=key.export_public_key(),
            fingerprint=key.get_fingerprint(),
            private_key_path=tmp_path / "user_ca",
        )
        database.record_certificate(
            ca_id=ca.ca_id,
            serial=7,
            identity="alice",
            public_key_fingerprint="SHA256:user-key",
            principals=("alice",),
            valid_after=1_700_000_000,
            valid_before=1_700_000_000 + 25 * 60 * 60,
            request_id="request-1",
            outcome="success",
        )
        with pytest.raises(DuplicateCertificateSerialError):
            database.record_certificate(
                ca_id=ca.ca_id,
                serial=7,
                identity="alice",
                public_key_fingerprint="SHA256:other-key",
                principals=("alice",),
                valid_after=1_700_000_000,
                valid_before=1_700_000_000 + 25 * 60 * 60,
                request_id="request-2",
                outcome="success",
            )
        with pytest.raises(StateError, match="25 hours"):
            database.record_certificate(
                ca_id=ca.ca_id,
                serial=8,
                identity="alice",
                public_key_fingerprint="SHA256:other-key",
                principals=("alice",),
                valid_after=1_700_000_000,
                valid_before=1_700_000_001,
                request_id="request-3",
                outcome="failed",
            )
    finally:
        database.close()


def test_principal_policy_canonicalizes_groups_and_rejects_duplicates() -> None:
    """Principal construction and validation share canonical identity grammar."""
    principals = build_principals("alice", ("platform-ops",))
    assert principals == ("alice", "group:platform-ops")
    assert validate_principals(principals) == principals

    with pytest.raises(PolicyValidationError):
        build_principals("alice", ("Platform-ops",))
    with pytest.raises(PolicyValidationError):
        validate_principals(("alice", "alice"))
