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
    IssuerIdentityProvider,
    SqliteIdentityStore,
    UserDetail,
    UserRecord,
    UserSummary,
)
from ski.state import StateDatabase, StateError
from support import raw_sqlite_connection


def test_identity_store_rejects_prebaseline_host_key_database(
    tmp_path: Path,
) -> None:
    """Identity access refuses a pre-baseline schema without migration."""
    database_path = tmp_path / "state.sqlite3"
    database = StateDatabase.open(database_path, owner=True)
    database.close()

    connection = sqlite3.connect(database_path)
    connection.execute("DROP TABLE user_groups")
    connection.execute("DROP TABLE groups")
    connection.execute("DROP TABLE users")
    connection.execute("UPDATE ski_schema SET version = 2 WHERE singleton = 1")
    connection.commit()
    connection.close()

    with pytest.raises(StateError, match="unsupported"):
        StateDatabase.open(database_path, owner=True)


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


def test_identity_store_exposes_secret_free_user_detail(
    tmp_path: Path,
) -> None:
    """Detailed administrative views contain status and groups, never credentials."""
    database = StateDatabase.open(tmp_path / "state.sqlite3", owner=True)
    try:
        store = SqliteIdentityStore(database)
        store.create_user("alice", "password", "JBSWY3DPEHPK3PXP")
        store.create_group("ops")
        store.add_membership("ops", "alice")

        detail = store.get_user_detail("alice")

        assert isinstance(detail, UserDetail)
        assert detail == UserDetail("alice", True, ("ops",))
        assert not hasattr(detail, "password_verifier")
        assert not hasattr(detail, "totp_secret")
    finally:
        database.close()


def test_identity_store_uses_only_the_public_state_unit_of_work(
    tmp_path: Path,
) -> None:
    """Identity authentication and groups work through R1's public boundary."""
    database = StateDatabase.open(tmp_path / "state.sqlite3", owner=True)

    class PublicStateBoundary:
        """Expose only the state operations used by the identity repository."""

        def __init__(self, state: StateDatabase) -> None:
            self._state = state

        @property
        def schema_version(self) -> int:
            return self._state.schema_version

        @property
        def table_names(self) -> frozenset[str]:
            return self._state.table_names

        def read_connection(self):
            return self._state.read_connection()

        def transaction(self):
            return self._state.transaction()

    try:
        store = SqliteIdentityStore(cast(StateDatabase, PublicStateBoundary(database)))
        store.create_user("alice", "password", "JBSWY3DPEHPK3PXP")
        store.create_group("ops")
        store.add_membership("ops", "alice")

        assert store.lookup_identity("alice") == "alice"
        assert store.verify_password("alice", "password")
        assert store.get_group_snapshot("alice").groups == ("ops",)
    finally:
        database.close()


def test_issuer_identity_contract_is_structural_and_read_only() -> None:
    """A minimal adapter satisfies the issuer capability without admin APIs."""

    class MinimalAdapter:
        def lookup_identity(self, username: str) -> str:
            return username

        def verify_password(self, username: str, password: str) -> bool:
            return username == "alice" and password == "password"

        def verify_totp(
            self,
            username: str,
            code: str,
            *,
            now: int | None = None,
        ) -> bool:
            del now
            return username == "alice" and code == "123456"

        def get_group_snapshot(self, username: str) -> IdentitySnapshot:
            return IdentitySnapshot(username=username, groups=("ops",))

    adapter = MinimalAdapter()
    assert isinstance(adapter, IssuerIdentityProvider)


def test_identity_store_contract_accepts_non_sqlite_implementation() -> None:
    """An authentication-facing boundary can use a store with no SQLite calls."""

    class FixtureIdentityStore(IdentityStore):
        def get_user(self, username: str) -> UserRecord:
            raise AssertionError("fixture should not use administration methods")

        def lookup_identity(self, username: str) -> str:
            raise AssertionError("fixture should not use administration methods")

        def get_group_snapshot(self, username: str) -> IdentitySnapshot:
            assert username == "alice"
            return IdentitySnapshot(username="alice", groups=("ops",))

        def get_user_detail(self, username: str) -> UserDetail:
            raise AssertionError("fixture should not use administration methods")

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

        def get_group_members(self, name: str) -> tuple[str, ...]:
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
        with raw_sqlite_connection(database.path) as connection:
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


def test_password_verification_uses_dummy_hasher_for_unknown_and_disabled_users(
    tmp_path: Path,
) -> None:
    """Unknown and disabled users still perform a dummy password verification."""

    class RecordingHasher:
        def __init__(self) -> None:
            self.hash_inputs: list[str] = []
            self.verifications: list[tuple[str, str]] = []

        def hash(self, password: str) -> str:
            self.hash_inputs.append(password)
            return f"hash:{password}"

        def verify(self, verifier: str, password: str) -> bool:
            self.verifications.append((verifier, password))
            return verifier == "hash:password" and password == "password"

        def check_needs_rehash(self, verifier: str) -> bool:
            del verifier
            return False

    database = StateDatabase.open(tmp_path / "state.sqlite3")
    try:
        hasher = RecordingHasher()
        store = SqliteIdentityStore(
            database,
            password_hasher=cast(PasswordHasher, hasher),
        )
        store.create_user("alice", "password", "JBSWY3DPEHPK3PXP")

        assert store.verify_password("missing", "password") is False
        store.set_user_enabled("alice", False)
        assert store.verify_password("alice", "password") is False

        assert hasher.hash_inputs == ["password", "ski-dummy-password"]
        assert hasher.verifications == [
            ("hash:ski-dummy-password", "password"),
            ("hash:ski-dummy-password", "password"),
        ]
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
