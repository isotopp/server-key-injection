"""Behavioural tests for foundational local service state."""

from __future__ import annotations

import sqlite3
import stat
from pathlib import Path

import pytest

from ski.state import StateDatabase, StateOwnershipError, UnsupportedSchemaError


def test_state_database_creates_only_foundational_schema(tmp_path: Path) -> None:
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
        assert database.schema_version == 1
        assert "ski_schema" in database.table_names
        assert "ca_keys" not in database.table_names
        assert "certificates" not in database.table_names
    finally:
        database.close()


def test_state_database_reopens_idempotently(tmp_path: Path) -> None:
    """A restart can reacquire the same supported schema."""
    database_path = tmp_path / "state.sqlite3"

    first = StateDatabase.open(database_path, owner=True)
    first.close()
    second = StateDatabase.open(database_path, owner=True)
    try:
        assert second.schema_version == 1
    finally:
        second.close()


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
