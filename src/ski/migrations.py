"""Ordered SQLite schema definitions for the supported state baseline."""

from __future__ import annotations

import sqlite3

CURRENT_SCHEMA_VERSION = 4


def create_schema_v4(connection: sqlite3.Connection) -> None:
    """Create the complete version-4 schema in migration order."""
    connection.execute(
        "CREATE TABLE IF NOT EXISTS ski_schema ("
        "singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
        "version INTEGER NOT NULL"
        ")",
    )
    connection.execute(
        "INSERT INTO ski_schema (singleton, version) VALUES (1, ?)",
        (CURRENT_SCHEMA_VERSION,),
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS ssh_host_keys ("
        "singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
        "algorithm TEXT NOT NULL, "
        "private_key BLOB NOT NULL, "
        "public_key BLOB NOT NULL, "
        "fingerprint TEXT NOT NULL"
        ")",
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "username TEXT PRIMARY KEY, "
        "password_verifier TEXT NOT NULL, "
        "totp_secret TEXT NOT NULL, "
        "enabled INTEGER NOT NULL CHECK (enabled IN (0, 1))"
        ")",
    )
    connection.execute("CREATE TABLE IF NOT EXISTS groups (name TEXT PRIMARY KEY)")
    connection.execute(
        "CREATE TABLE IF NOT EXISTS user_groups ("
        "username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE, "
        "group_name TEXT NOT NULL REFERENCES groups(name) ON DELETE CASCADE, "
        "PRIMARY KEY (username, group_name)"
        ")",
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS ca_keys ("
        "ca_id INTEGER PRIMARY KEY, "
        "algorithm TEXT NOT NULL CHECK (algorithm = 'ssh-ed25519'), "
        "public_key BLOB NOT NULL, "
        "fingerprint TEXT NOT NULL UNIQUE, "
        "private_key_path TEXT NOT NULL, "
        "activated_at INTEGER NOT NULL, "
        "status TEXT NOT NULL CHECK (status IN ('active', 'retired'))"
        ")",
    )
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ca_keys_one_active "
        "ON ca_keys (status) WHERE status = 'active'",
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS certificates ("
        "certificate_id INTEGER PRIMARY KEY, "
        "ca_id INTEGER NOT NULL REFERENCES ca_keys(ca_id), "
        "serial TEXT NOT NULL, "
        "identity TEXT NOT NULL, "
        "public_key_fingerprint TEXT NOT NULL, "
        "principals TEXT NOT NULL, "
        "valid_after INTEGER NOT NULL, "
        "valid_before INTEGER NOT NULL, "
        "request_id TEXT NOT NULL, "
        "outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failed')), "
        "UNIQUE (ca_id, serial)"
        ")",
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS events ("
        "event_id INTEGER PRIMARY KEY, "
        "occurred_at INTEGER NOT NULL, "
        "kind TEXT NOT NULL, "
        "decision TEXT NOT NULL, "
        "request_id TEXT NOT NULL, "
        "identity TEXT, "
        "ca_id INTEGER REFERENCES ca_keys(ca_id), "
        "serial TEXT"
        ")",
    )
    connection.execute(
        "CREATE TRIGGER IF NOT EXISTS events_no_update "
        "BEFORE UPDATE ON events BEGIN "
        "SELECT RAISE(ABORT, 'events are append-only'); END",
    )
    connection.execute(
        "CREATE TRIGGER IF NOT EXISTS events_no_delete "
        "BEFORE DELETE ON events BEGIN "
        "SELECT RAISE(ABORT, 'events are append-only'); END",
    )
