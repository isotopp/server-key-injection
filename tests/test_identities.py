"""Behavioural tests for the replaceable demo identity store."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import cast

import pyotp
import pytest
from argon2 import PasswordHasher

from ski.identities import (
    IdentityAlreadyExistsError,
    IdentityDataError,
    IdentityDisabledError,
    IdentityNotFoundError,
    IdentitySnapshot,
    IdentityStore,
    IdentityUnavailableError,
    IdentityValidationError,
    SqliteIdentityStore,
    UserRecord,
    UserSummary,
)
from ski.state import StateDatabase


def test_identity_store_migrates_host_key_database_without_ca_state(
    tmp_path: Path,
) -> None:
    """Identity tables extend the host-key schema without replacing it."""
    database_path = tmp_path / "state.sqlite3"
    database = StateDatabase.open(database_path, owner=True)
    try:
        original_host_key = database.host_key
    finally:
        database.close()

    connection = sqlite3.connect(database_path)
    connection.execute("DROP TABLE user_groups")
    connection.execute("DROP TABLE groups")
    connection.execute("DROP TABLE users")
    connection.execute("UPDATE ski_schema SET version = 2 WHERE singleton = 1")
    connection.commit()
    connection.close()

    database = StateDatabase.open(database_path, owner=True)
    try:
        store = SqliteIdentityStore(database)

        assert store.schema_version == 3
        assert store.table_names == frozenset(
            {"ski_schema", "ssh_host_keys", "users", "groups", "user_groups"},
        )
        assert database.host_key.fingerprint == original_host_key.fingerprint
    finally:
        database.close()


def test_identity_store_rejects_noncanonical_and_duplicate_identifiers(
    tmp_path: Path,
) -> None:
    """Invalid identifiers and duplicates leave no partial identity rows."""
    database = StateDatabase.open(tmp_path / "state.sqlite3", owner=True)
    try:
        store = SqliteIdentityStore(database)
        for username in ("Alice", "ümlaut", "a" * 33, "-bad", ""):
            with pytest.raises(IdentityValidationError):
                store.create_user(username, "password", "JBSWY3DPEHPK3PXP")
        assert store.list_users() == ()

        store.create_user("alice", "password", "JBSWY3DPEHPK3PXP")
        with pytest.raises(IdentityAlreadyExistsError):
            store.create_user("alice", "password", "JBSWY3DPEHPK3PXP")
        assert tuple(user.username for user in store.list_users()) == ("alice",)

        for group in ("Platform", "ümlaut", "a" * 64, "a_b", ""):
            with pytest.raises(IdentityValidationError):
                store.create_group(group)
        assert store.list_groups() == ()

        store.create_group("platform")
        with pytest.raises(IdentityAlreadyExistsError):
            store.create_group("platform")
        assert store.list_groups() == ("platform",)
    finally:
        database.close()


def test_identity_store_returns_stable_snapshots_and_fails_closed(
    tmp_path: Path,
) -> None:
    """Group snapshots are immutable and every identity-data failure is explicit."""
    database = StateDatabase.open(tmp_path / "state.sqlite3", owner=True)
    store = SqliteIdentityStore(database)
    try:
        store.create_user("alice", "password", "JBSWY3DPEHPK3PXP")
        store.create_group("ops")
        store.create_group("database")
        store.add_membership("ops", "alice")
        store.add_membership("database", "alice")

        snapshot = store.get_group_snapshot("alice")
        assert snapshot.username == "alice"
        assert snapshot.groups == ("database", "ops")

        store.create_group("platform")
        store.add_membership("platform", "alice")
        assert snapshot.groups == ("database", "ops")
        assert store.get_group_snapshot("alice").groups == (
            "database",
            "ops",
            "platform",
        )

        with pytest.raises(IdentityNotFoundError):
            store.get_group_snapshot("missing")
        store.set_user_enabled("alice", False)
        with pytest.raises(IdentityDisabledError):
            store.get_group_snapshot("alice")
        store.set_user_enabled("alice", True)

        connection = sqlite3.connect(database.path)
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute(
            "UPDATE user_groups SET group_name = 'Malformed' "
            "WHERE username = 'alice' AND group_name = 'ops'",
        )
        connection.commit()
        connection.close()
        with pytest.raises(IdentityDataError):
            store.get_group_snapshot("alice")
    finally:
        database.close()

    with pytest.raises(IdentityUnavailableError):
        store.get_group_snapshot("alice")


def test_identity_store_contract_accepts_non_sqlite_implementation() -> None:
    """An authentication-facing boundary can use a store with no SQLite calls."""

    class FixtureIdentityStore(IdentityStore):
        def get_user(self, username: str) -> UserRecord:
            raise AssertionError("fixture should not use administration methods")

        def get_group_snapshot(self, username: str) -> IdentitySnapshot:
            assert username == "alice"
            return IdentitySnapshot(username="alice", groups=("ops",))

        def create_user(
            self, username: str, password: str, totp_secret: str
        ) -> UserRecord:
            raise AssertionError("fixture should not use administration methods")

        def list_users(self) -> tuple[UserSummary, ...]:
            raise AssertionError("fixture should not use administration methods")

        def set_user_enabled(self, username: str, enabled: bool) -> UserRecord:
            raise AssertionError("fixture should not use administration methods")

        def replace_password(self, username: str, password: str) -> UserRecord:
            raise AssertionError("fixture should not use administration methods")

        def replace_totp_secret(self, username: str, totp_secret: str) -> UserRecord:
            raise AssertionError("fixture should not use administration methods")

        def verify_password(self, username: str, password: str) -> bool:
            raise AssertionError("fixture should not use administration methods")

        def verify_totp(
            self,
            username: str,
            code: str,
            *,
            now: int | None = None,
        ) -> bool:
            raise AssertionError("fixture should not use administration methods")

        def create_group(self, name: str) -> None:
            raise AssertionError("fixture should not use administration methods")

        def list_groups(self) -> tuple[str, ...]:
            raise AssertionError("fixture should not use administration methods")

        def remove_group(self, name: str) -> None:
            raise AssertionError("fixture should not use administration methods")

        def add_membership(self, group: str, username: str) -> None:
            raise AssertionError("fixture should not use administration methods")

        def remove_membership(self, group: str, username: str) -> None:
            raise AssertionError("fixture should not use administration methods")

    def authenticate_request(store: IdentityStore, username: str) -> IdentitySnapshot:
        return store.get_group_snapshot(username)

    fixture = FixtureIdentityStore()
    snapshot = authenticate_request(fixture, "alice")
    assert snapshot.username == "alice"
    assert snapshot.groups == ("ops",)


def test_successful_password_verification_rehashes_outdated_parameters(
    tmp_path: Path,
) -> None:
    """Only a verified password may replace an outdated Argon2 verifier."""

    class RehashingHasher:
        def __init__(self) -> None:
            self.hash_calls = 0

        def hash(self, password: str) -> str:
            assert password == "password"
            self.hash_calls += 1
            return "$argon2id$new"

        def verify(self, verifier: str, password: str) -> bool:
            return (
                verifier in {"$argon2id$new", "$argon2id$old"}
                and password == "password"
            )

        def check_needs_rehash(self, verifier: str) -> bool:
            return verifier == "$argon2id$old"

    database = StateDatabase.open(tmp_path / "state.sqlite3")
    try:
        hasher = RehashingHasher()
        store = SqliteIdentityStore(
            database,
            password_hasher=cast(PasswordHasher, hasher),
        )
        store.create_user("alice", "password", "JBSWY3DPEHPK3PXP")
        connection = database._connection  # noqa: SLF001
        connection.execute(
            "UPDATE users SET password_verifier = '$argon2id$old' "
            "WHERE username = 'alice'",
        )
        connection.commit()

        assert store.verify_password("alice", "wrong") is False
        assert store.get_user("alice").password_verifier == "$argon2id$old"
        assert store.verify_password("alice", "password") is True
        assert store.get_user("alice").password_verifier == "$argon2id$new"
        assert hasher.hash_calls == 2
    finally:
        database.close()


def test_failed_credential_replacement_preserves_prior_working_material(
    tmp_path: Path,
) -> None:
    """Malformed replacements never partially replace a working credential."""
    database = StateDatabase.open(tmp_path / "state.sqlite3")
    try:
        store = SqliteIdentityStore(database)
        original = store.create_user("alice", "password", "JBSWY3DPEHPK3PXP")
        with pytest.raises(IdentityValidationError):
            store.replace_password("alice", "")
        with pytest.raises(IdentityValidationError):
            store.replace_totp_secret("alice", "")

        current = store.get_user("alice")
        assert current.password_verifier == original.password_verifier
        assert current.totp_secret == original.totp_secret
        assert store.verify_password("alice", "password")
        assert store.verify_totp("alice", pyotp.TOTP(original.totp_secret).now())
    finally:
        database.close()
