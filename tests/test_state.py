"""Behavioural tests for foundational local service state."""

from __future__ import annotations

import sqlite3
import stat
from pathlib import Path

import asyncssh
import pytest

from ski.state import (
    StateDatabase,
    StateError,
    StateOwnershipError,
    UnsupportedSchemaError,
)


def test_state_database_rejects_schema_three_with_persistent_ca_state(
    tmp_path: Path,
) -> None:
    """A pre-baseline state database is rejected without migration."""
    database_path = tmp_path / "state.sqlite3"
    connection = sqlite3.connect(database_path)
    connection.executescript(
        """
        CREATE TABLE ski_schema (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            version INTEGER NOT NULL
        );
        INSERT INTO ski_schema VALUES (1, 3);
        CREATE TABLE ssh_host_keys (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            algorithm TEXT NOT NULL,
            private_key BLOB NOT NULL,
            public_key BLOB NOT NULL,
            fingerprint TEXT NOT NULL
        );
        CREATE TABLE users (
            username TEXT PRIMARY KEY,
            password_verifier TEXT NOT NULL,
            totp_secret TEXT NOT NULL,
            enabled INTEGER NOT NULL CHECK (enabled IN (0, 1))
        );
        CREATE TABLE groups (name TEXT PRIMARY KEY);
        CREATE TABLE user_groups (
            username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
            group_name TEXT NOT NULL REFERENCES groups(name) ON DELETE CASCADE,
            PRIMARY KEY (username, group_name)
        );
        INSERT INTO users VALUES ('alice', 'verifier', 'JBSWY3DPEHPK3PXP', 1);
        INSERT INTO groups VALUES ('platform-ops');
        INSERT INTO user_groups VALUES ('alice', 'platform-ops');
        """,
    )
    connection.commit()
    connection.close()

    with pytest.raises(StateError, match="unsupported"):
        StateDatabase.open(database_path, owner=True)


@pytest.mark.parametrize("version", [1, 2, 3])
def test_state_database_rejects_unpublished_schema_versions(
    tmp_path: Path,
    version: int,
) -> None:
    """Development-only schema versions are not accepted as compatibility data."""
    database_path = tmp_path / "state.sqlite3"
    connection = sqlite3.connect(database_path)
    connection.execute(
        "CREATE TABLE ski_schema ("
        "singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
        "version INTEGER NOT NULL"
        ")",
    )
    connection.execute("INSERT INTO ski_schema VALUES (1, ?)", (version,))
    connection.commit()
    connection.close()

    with pytest.raises(StateError, match="unsupported"):
        StateDatabase.open(database_path, owner=True)


def test_state_database_registers_one_validated_active_ca(tmp_path: Path) -> None:
    """CA state exposes public metadata and refuses a second active signer."""
    database = StateDatabase.open(tmp_path / "state.sqlite3", owner=True)
    try:
        key = asyncssh.generate_private_key("ssh-ed25519")
        record = database.register_active_ca(
            public_key=key.export_public_key(),
            fingerprint=key.get_fingerprint(),
            private_key_path=tmp_path / "user_ca",
            activated_at=1_700_000_000,
        )
        assert record.algorithm == "ssh-ed25519"
        assert record.public_key == key.export_public_key()
        assert record.private_key_path == tmp_path / "user_ca"
        assert database.get_active_ca() == record
        assert database.list_ca_keys() == (record,)

        with pytest.raises(StateError, match="active CA"):
            database.register_active_ca(
                public_key=key.export_public_key(),
                fingerprint=key.get_fingerprint(),
                private_key_path=tmp_path / "other_ca",
            )
    finally:
        database.close()


def test_state_database_rejects_malformed_or_mismatched_ca_public_data(
    tmp_path: Path,
) -> None:
    """CA registration never records unverifiable public material."""
    database = StateDatabase.open(tmp_path / "state.sqlite3", owner=True)
    try:
        key = asyncssh.generate_private_key("ssh-ed25519")
        other_key = asyncssh.generate_private_key("ssh-ed25519")
        with pytest.raises(StateError, match="fingerprint"):
            database.register_active_ca(
                public_key=key.export_public_key(),
                fingerprint=other_key.get_fingerprint(),
                private_key_path=tmp_path / "user_ca",
            )
        with pytest.raises(StateError, match="public key"):
            database.register_active_ca(
                public_key=b"not-a-key",
                fingerprint="SHA256:not-a-key",
                private_key_path=tmp_path / "user_ca",
            )
        assert database.get_active_ca() is None
    finally:
        database.close()


def test_state_database_records_safe_certificate_metadata_and_serials(
    tmp_path: Path,
) -> None:
    """Issuance records retain public evidence and enforce per-CA serials."""
    database = StateDatabase.open(tmp_path / "state.sqlite3", owner=True)
    try:
        key = asyncssh.generate_private_key("ssh-ed25519")
        ca = database.register_active_ca(
            public_key=key.export_public_key(),
            fingerprint=key.get_fingerprint(),
            private_key_path=tmp_path / "user_ca",
        )
        record = database.record_certificate(
            ca_id=ca.ca_id,
            serial=2**64 - 1,
            identity="alice",
            public_key_fingerprint="SHA256:user-key",
            principals=("alice", "group:platform-ops"),
            valid_after=1_700_000_000,
            valid_before=1_700_090_000,
            request_id="request-1",
            outcome="success",
        )
        assert database.list_certificates() == (record,)
        with pytest.raises(StateError, match="serial"):
            database.record_certificate(
                ca_id=ca.ca_id,
                serial=2**64 - 1,
                identity="alice",
                public_key_fingerprint="SHA256:other-key",
                principals=("alice",),
                valid_after=1_700_000_000,
                valid_before=1_700_090_000,
                request_id="request-2",
                outcome="success",
            )
        with pytest.raises(StateError, match="25 hours"):
            database.record_certificate(
                ca_id=ca.ca_id,
                serial=1,
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


def test_state_database_appends_redacted_events_without_update_or_delete(
    tmp_path: Path,
) -> None:
    """CA events are stable, ordered, and append-only at the SQLite boundary."""
    database = StateDatabase.open(tmp_path / "state.sqlite3", owner=True)
    try:
        first = database.record_event(
            kind="ca_initialized",
            decision="allow",
            request_id="request-1",
            occurred_at=1_700_000_000,
            identity="alice",
        )
        second = database.record_event(
            kind="certificate_issued",
            decision="deny",
            request_id="request-2",
            occurred_at=1_700_000_001,
        )
        assert database.list_events() == (first, second)
        rendered = repr(database.list_events())
        assert "PRIVATE KEY" not in rendered
        assert "password" not in rendered.lower()

        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            with database.transaction() as connection:
                connection.execute(
                    "UPDATE events SET decision = 'tampered' WHERE event_id = ?",
                    (first.event_id,),
                )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            with database.transaction() as connection:
                connection.execute(
                    "DELETE FROM events WHERE event_id = ?",
                    (first.event_id,),
                )
    finally:
        database.close()


def test_state_database_fails_closed_on_corrupt_persisted_ca_record(
    tmp_path: Path,
) -> None:
    """Corrupt CA rows are rejected rather than replaced or ignored."""
    database_path = tmp_path / "state.sqlite3"
    database = StateDatabase.open(database_path, owner=True)
    try:
        key = asyncssh.generate_private_key("ssh-ed25519")
        ca = database.register_active_ca(
            public_key=key.export_public_key(),
            fingerprint=key.get_fingerprint(),
            private_key_path=tmp_path / "user_ca",
        )
        assert database.get_active_ca() == ca
        with database.transaction() as connection:
            connection.execute(
                "UPDATE ca_keys SET fingerprint = 'SHA256:tampered' WHERE ca_id = ?",
                (ca.ca_id,),
            )
    finally:
        database.close()

    reopened = StateDatabase.open(database_path, owner=True)
    try:
        with pytest.raises(StateError, match="fingerprint"):
            reopened.get_active_ca()
    finally:
        reopened.close()


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
    """First service startup creates the protected current state schema."""
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
        assert database.schema_version == 4
        assert "ski_schema" in database.table_names
        assert "ssh_host_keys" in database.table_names
        assert {"users", "groups", "user_groups"} <= database.table_names
        assert {"ca_keys", "certificates", "events"} <= database.table_names
    finally:
        database.close()


def test_state_schema_contains_only_current_demo_tables(tmp_path: Path) -> None:
    """The current schema has no revocation or production-host tables."""
    database = StateDatabase.open(tmp_path / "state.sqlite3", owner=True)
    try:
        assert database.table_names == {
            "ski_schema",
            "ssh_host_keys",
            "users",
            "groups",
            "user_groups",
            "ca_keys",
            "certificates",
            "events",
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
        assert second.schema_version == 4
    finally:
        second.close()


def test_state_database_rejects_foundation_schema(
    tmp_path: Path,
) -> None:
    """An unpublished foundation schema is rejected without regeneration."""
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

    with pytest.raises(StateError, match="unsupported"):
        StateDatabase.open(database_path, owner=True)


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
