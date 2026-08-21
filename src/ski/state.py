"""Local SQLite state and service-instance ownership."""

from __future__ import annotations

import fcntl
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO, cast

import asyncssh

SUPPORTED_SCHEMA_VERSION = 3


@dataclass(frozen=True)
class HostKeyMaterial:
    """Validated Ed25519 material owned by the local state database."""

    algorithm: str
    private_key: bytes = field(repr=False)
    public_key: bytes
    fingerprint: str


class StateError(RuntimeError):
    """Base error for local service state failures."""


class StateOwnershipError(StateError):
    """Raised when another daemon owns the configured state database."""


class UnsupportedSchemaError(StateError):
    """Raised when a database requires a newer schema than this service knows."""


class StateDatabase:
    """Own a SQLite connection and optionally the daemon instance lock."""

    def __init__(
        self,
        *,
        path: Path,
        connection: sqlite3.Connection,
        lock_file: TextIO | None,
    ) -> None:
        self.path = path
        self._connection = connection
        self._lock_file = lock_file
        self._host_key: HostKeyMaterial | None = None

    @classmethod
    def open(cls, path: Path, *, owner: bool = False) -> StateDatabase:
        """Open foundational state, optionally acquiring daemon ownership."""
        path = Path(path).expanduser()
        if not path.parent.is_dir():
            raise StateError("state database parent directory is unavailable")
        if owner:
            lock_file = cls._acquire_lock(path)
        else:
            lock_file = None

        connection: sqlite3.Connection | None = None
        try:
            existed = path.exists()
            if not existed:
                path.touch(mode=0o600)
            path.chmod(0o600)
            connection = sqlite3.connect(path, timeout=5.0, isolation_level=None)
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            cls._initialize_schema(connection)
        except Exception:
            if connection is not None:
                connection.close()
            if lock_file is not None:
                cls._release_lock(lock_file)
            raise
        assert connection is not None
        return cls(path=path, connection=connection, lock_file=lock_file)

    @staticmethod
    def _acquire_lock(path: Path) -> TextIO:
        lock_path = path.with_name(f"{path.name}.lock")
        lock_path.touch(mode=0o600, exist_ok=True)
        lock_path.chmod(0o600)
        lock_file = lock_path.open("r+")
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            lock_file.close()
            raise StateOwnershipError("state database is already owned") from exc
        return lock_file

    @staticmethod
    def _release_lock(lock_file: TextIO) -> None:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        lock_file.close()

    @staticmethod
    def _initialize_schema(connection: sqlite3.Connection) -> None:
        schema_exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'ski_schema'",
        ).fetchone()
        row = (
            connection.execute(
                "SELECT version FROM ski_schema WHERE singleton = 1",
            ).fetchone()
            if schema_exists
            else None
        )
        if row is not None:
            if row[0] > SUPPORTED_SCHEMA_VERSION:
                raise UnsupportedSchemaError("state database schema is newer")
            if row[0] == 1:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    StateDatabase._create_host_key_table(connection)
                    connection.execute(
                        "UPDATE ski_schema SET version = ? WHERE singleton = 1",
                        (SUPPORTED_SCHEMA_VERSION,),
                    )
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
                row = (2,)
            if row[0] == 2:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    StateDatabase._create_identity_tables(connection)
                    connection.execute(
                        "UPDATE ski_schema SET version = ? WHERE singleton = 1",
                        (SUPPORTED_SCHEMA_VERSION,),
                    )
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
                return
            if row[0] != SUPPORTED_SCHEMA_VERSION:
                raise StateError("state database schema version is unsupported")
            return

        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS ski_schema ("
                "singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
                "version INTEGER NOT NULL"
                ")",
            )
            connection.execute(
                "INSERT INTO ski_schema (singleton, version) VALUES (1, ?)",
                (SUPPORTED_SCHEMA_VERSION,),
            )
            StateDatabase._create_host_key_table(connection)
            StateDatabase._create_identity_tables(connection)
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    @staticmethod
    def _create_host_key_table(connection: sqlite3.Connection) -> None:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS ssh_host_keys ("
            "singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
            "algorithm TEXT NOT NULL, "
            "private_key BLOB NOT NULL, "
            "public_key BLOB NOT NULL, "
            "fingerprint TEXT NOT NULL"
            ")",
        )

    @staticmethod
    def _create_identity_tables(connection: sqlite3.Connection) -> None:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            "username TEXT PRIMARY KEY, "
            "password_verifier TEXT NOT NULL, "
            "totp_secret TEXT NOT NULL, "
            "enabled INTEGER NOT NULL CHECK (enabled IN (0, 1))"
            ")",
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS groups (name TEXT PRIMARY KEY)",
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS user_groups ("
            "username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE, "
            "group_name TEXT NOT NULL REFERENCES groups(name) ON DELETE CASCADE, "
            "PRIMARY KEY (username, group_name)"
            ")",
        )

    @property
    def host_key(self) -> HostKeyMaterial:
        """Return the validated persistent Ed25519 SSH host identity."""
        if self._host_key is not None:
            return self._host_key

        row = self._connection.execute(
            "SELECT algorithm, private_key, public_key, fingerprint "
            "FROM ssh_host_keys WHERE singleton = 1",
        ).fetchone()
        if row is None:
            material = self._new_host_key()
            with self.transaction() as connection:
                connection.execute(
                    "INSERT INTO ssh_host_keys "
                    "(singleton, algorithm, private_key, public_key, fingerprint) "
                    "VALUES (1, ?, ?, ?, ?)",
                    (
                        material.algorithm,
                        material.private_key,
                        material.public_key,
                        material.fingerprint,
                    ),
                )
            self._host_key = material
            return material

        material = self._validate_host_key_row(row)
        self._host_key = material
        return material

    @staticmethod
    def _new_host_key() -> HostKeyMaterial:
        key = asyncssh.generate_private_key("ssh-ed25519")
        return HostKeyMaterial(
            algorithm="ssh-ed25519",
            private_key=key.export_private_key(),
            public_key=key.export_public_key(),
            fingerprint=key.get_fingerprint(),
        )

    @staticmethod
    def _validate_host_key_row(row: tuple[object, ...]) -> HostKeyMaterial:
        algorithm, private_key, public_key, fingerprint = row
        if algorithm != "ssh-ed25519":
            raise StateError("stored SSH host key algorithm is unsupported")
        if not all(
            isinstance(value, (bytes, bytearray)) for value in (private_key, public_key)
        ) or not isinstance(fingerprint, str):
            raise StateError("stored SSH host key is malformed")
        algorithm_value = cast(str, algorithm)
        private_bytes = bytes(cast(bytes | bytearray, private_key))
        public_bytes = bytes(cast(bytes | bytearray, public_key))
        try:
            key = asyncssh.import_private_key(private_bytes)
        except Exception as exc:
            raise StateError("stored SSH host key is invalid") from exc
        if key.export_public_key() != public_bytes:
            raise StateError("stored SSH host key public data does not match")
        if key.get_fingerprint() != fingerprint:
            raise StateError("stored SSH host key fingerprint does not match")
        return HostKeyMaterial(
            algorithm=algorithm_value,
            private_key=private_bytes,
            public_key=public_bytes,
            fingerprint=fingerprint,
        )

    @property
    def schema_version(self) -> int:
        """Return the supported schema version in this database."""
        row = self._connection.execute(
            "SELECT version FROM ski_schema WHERE singleton = 1",
        ).fetchone()
        if row is None:
            raise StateError("state schema is not initialized")
        return int(row[0])

    @property
    def table_names(self) -> frozenset[str]:
        """Return application table names for operational inspection."""
        rows = self._connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        )
        return frozenset(row[0] for row in rows)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Run one explicit short transaction which commits or rolls back."""
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            yield self._connection
        except Exception:
            self._connection.rollback()
            raise
        else:
            self._connection.commit()

    def close(self) -> None:
        """Close the database and release daemon ownership idempotently."""
        connection = self._connection
        self._connection = sqlite3.Connection(":memory:")
        connection.close()
        if self._lock_file is not None:
            lock_file = self._lock_file
            self._lock_file = None
            self._release_lock(lock_file)
