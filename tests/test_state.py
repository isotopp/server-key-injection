"""Behavioural tests for foundational local service state."""

from __future__ import annotations

import sqlite3
import stat
from pathlib import Path

import pytest

from ski.state import (
    StateDatabase,
    StateError,
    StateOwnershipError,
    UnsupportedSchemaError,
)


def test_state_database_persists_one_issuer_host_identity(tmp_path: Path) -> None:
    """A database owns one stable Ed25519 host identity across reopenings."""
    database_path = tmp_path / "state.sqlite3"

    first = StateDatabase.open(database_path, owner=True)
    try:
        first_key = first.host_key
        assert first_key.algorithm == "ssh-ed25519"
        assert first_key.fingerprint.startswith("SHA256:")
        assert "ssh_host_keys" in first.table_names
    finally:
        first.close()

    second = StateDatabase.open(database_path, owner=True)
    try:
        assert second.host_key.fingerprint == first_key.fingerprint
        assert second.host_key.public_key == first_key.public_key
    finally:
        second.close()


def test_state_database_creates_only_non_ca_schema(tmp_path: Path) -> None:
    """First service startup creates protected non-CA state."""
    database_path = tmp_path / "state.sqlite3"

    database = StateDatabase.open(database_path, owner=True)
    try:
        assert database_path.is_file()
        assert stat.S_IMODE(database_path.stat().st_mode) == 0o600
        assert (
            stat.S_IMODE(
                database_path.with_name("state.sqlite3.lock").stat().st_mode,
            )
            == 0o600
        )
        assert database.schema_version == 3
        assert "ski_schema" in database.table_names
        assert "ssh_host_keys" in database.table_names
        assert {"users", "groups", "user_groups"} <= database.table_names
        assert "ca_keys" not in database.table_names
        assert "certificates" not in database.table_names
    finally:
        database.close()


def test_state_schema_contains_only_current_demo_tables(tmp_path: Path) -> None:
    """The Epic 3 database has no CA, certificate, revocation, or audit tables."""
    database = StateDatabase.open(tmp_path / "state.sqlite3", owner=True)
    try:
        assert database.table_names == {
            "ski_schema",
            "ssh_host_keys",
            "users",
            "groups",
            "user_groups",
        }
    finally:
        database.close()


def test_state_database_reopens_idempotently(tmp_path: Path) -> None:
    """A restart can reacquire the same supported schema."""
    database_path = tmp_path / "state.sqlite3"

    first = StateDatabase.open(database_path, owner=True)
    first.close()
    second = StateDatabase.open(database_path, owner=True)
    try:
        assert second.schema_version == 3
    finally:
        second.close()


def test_state_database_migrates_foundation_to_host_key_schema(
    tmp_path: Path,
) -> None:
    """An Epic 2 database gains host-key state without losing its foundation."""
    database_path = tmp_path / "state.sqlite3"
    connection = sqlite3.connect(database_path)
    connection.execute(
        "CREATE TABLE ski_schema ("
        "singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
        "version INTEGER NOT NULL"
        ")",
    )
    connection.execute("INSERT INTO ski_schema VALUES (1, 1)")
    connection.commit()
    connection.close()

    database = StateDatabase.open(database_path, owner=True)
    try:
        assert database.schema_version == 3
        assert "ssh_host_keys" in database.table_names
        assert {"users", "groups", "user_groups"} <= database.table_names
        assert database.host_key.fingerprint.startswith("SHA256:")
    finally:
        database.close()


def test_state_database_rejects_tampered_host_identity_without_regeneration(
    tmp_path: Path,
) -> None:
    """Corrupt host-key material fails closed and is never silently replaced."""
    database_path = tmp_path / "state.sqlite3"
    database = StateDatabase.open(database_path, owner=True)
    try:
        _ = database.host_key
    finally:
        database.close()

    connection = sqlite3.connect(database_path)
    connection.execute(
        "UPDATE ssh_host_keys SET algorithm = 'ssh-rsa' WHERE singleton = 1",
    )
    connection.commit()
    connection.close()

    database = StateDatabase.open(database_path, owner=True)
    try:
        with pytest.raises(StateError, match="algorithm is unsupported"):
            _ = database.host_key
    finally:
        database.close()

    connection = sqlite3.connect(database_path)
    assert connection.execute(
        "SELECT algorithm FROM ssh_host_keys WHERE singleton = 1",
    ).fetchone() == ("ssh-rsa",)
    connection.close()


def test_newer_state_schema_fails_closed(tmp_path: Path) -> None:
    """A database from a newer service is not modified or opened."""
    database_path = tmp_path / "state.sqlite3"
    connection = sqlite3.connect(database_path)
    connection.execute(
        "CREATE TABLE ski_schema ("
        "singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
        "version INTEGER NOT NULL"
        ")",
    )
    connection.execute("INSERT INTO ski_schema VALUES (1, 99)")
    connection.commit()
    connection.close()

    with pytest.raises(UnsupportedSchemaError):
        StateDatabase.open(database_path, owner=True)

    connection = sqlite3.connect(database_path)
    assert connection.execute("SELECT version FROM ski_schema").fetchone() == (99,)
    connection.close()


def test_state_transactions_commit_and_rollback_as_units(tmp_path: Path) -> None:
    """Short state writes commit together or leave no partial schema."""
    database = StateDatabase.open(tmp_path / "state.sqlite3", owner=True)
    try:
        with database.transaction() as connection:
            connection.execute(
                "CREATE TABLE committed_state (value TEXT NOT NULL)",
            )
            connection.execute("INSERT INTO committed_state VALUES ('ok')")

        assert "committed_state" in database.table_names

        with pytest.raises(RuntimeError):
            with database.transaction() as connection:
                connection.execute(
                    "CREATE TABLE rolled_back_state (value TEXT NOT NULL)",
                )
                raise RuntimeError("test rollback")

        assert "rolled_back_state" not in database.table_names
    finally:
        database.close()


def test_only_one_daemon_owns_state_but_admin_access_remains_available(
    tmp_path: Path,
) -> None:
    """The instance lock excludes daemons, not short admin transactions."""
    database_path = tmp_path / "state.sqlite3"
    owner = StateDatabase.open(database_path, owner=True)
    try:
        with pytest.raises(StateOwnershipError):
            StateDatabase.open(database_path, owner=True)

        admin = StateDatabase.open(database_path)
        try:
            with admin.transaction() as connection:
                connection.execute("CREATE TABLE admin_state (value TEXT NOT NULL)")
                connection.execute("INSERT INTO admin_state VALUES ('ok')")
            assert "admin_state" in admin.table_names
        finally:
            admin.close()
    finally:
        owner.close()

    reacquired = StateDatabase.open(database_path, owner=True)
    reacquired.close()
