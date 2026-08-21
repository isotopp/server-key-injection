"""Local SQLite state and service-instance ownership."""

from __future__ import annotations

import fcntl
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO, cast

import asyncssh

from ski.policy import PolicyValidationError, validate_principals, validate_username

SUPPORTED_SCHEMA_VERSION = 4
ORDINARY_CERTIFICATE_LIFETIME = 25 * 60 * 60
_SERIAL_MAX = 2**64 - 1


@dataclass(frozen=True)
class HostKeyMaterial:
    """Validated Ed25519 material owned by the local state database."""

    algorithm: str
    private_key: bytes = field(repr=False)
    public_key: bytes
    fingerprint: str


@dataclass(frozen=True, slots=True)
class CAKeyRecord:
    """Public metadata for one persisted user-CA record."""

    ca_id: int
    algorithm: str
    public_key: bytes
    fingerprint: str
    private_key_path: Path
    activated_at: int
    status: str


@dataclass(frozen=True, slots=True)
class CertificateRecord:
    """Safe metadata for one ordinary certificate issuance attempt."""

    certificate_id: int
    ca_id: int
    serial: int
    identity: str
    public_key_fingerprint: str
    principals: tuple[str, ...]
    valid_after: int
    valid_before: int
    request_id: str
    outcome: str


@dataclass(frozen=True, slots=True)
class EventRecord:
    """One append-only, secret-free CA event."""

    event_id: int
    occurred_at: int
    kind: str
    decision: str
    request_id: str
    identity: str | None
    ca_id: int | None
    serial: int | None


class StateError(RuntimeError):
    """Base error for local service state failures."""


class StateOwnershipError(StateError):
    """Raised when another daemon owns the configured state database."""


class UnsupportedSchemaError(StateError):
    """Raised when a database requires a newer schema than this service knows."""


def _timestamp(value: int | float | datetime | None) -> int:
    if value is None:
        return int(datetime.now(UTC).timestamp())
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise StateError("timestamp must include a timezone")
        return int(value.astimezone(UTC).timestamp())
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise StateError("timestamp is malformed")
    result = int(value)
    if result < 0:
        raise StateError("timestamp is malformed")
    return result


def _validate_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise StateError(f"{label} is malformed")
    return value


def _validate_positive_id(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise StateError(f"{label} is malformed")
    return value


def _validate_serial(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StateError("certificate serial is malformed")
    if not 0 <= value <= _SERIAL_MAX:
        raise StateError("certificate serial is outside the 64-bit range")
    return value


def _validate_identity(value: object) -> str:
    try:
        return validate_username(value)
    except PolicyValidationError as exc:
        raise StateError("identity is not canonical") from exc


def _validate_principals(value: object) -> tuple[str, ...]:
    try:
        return validate_principals(value)
    except PolicyValidationError as exc:
        raise StateError(str(exc)) from exc


def _validate_outcome(value: object) -> str:
    if value not in {"success", "failed"}:
        raise StateError("certificate outcome is malformed")
    return cast(str, value)


def _validated_certificate_fields(
    *,
    ca_id: int,
    serial: int,
    identity: str,
    public_key_fingerprint: str,
    principals: tuple[str, ...],
    valid_after: int,
    valid_before: int,
    request_id: str,
    outcome: str,
) -> tuple[int, int, str, str, tuple[str, ...], int, int, str, str, str]:
    _validate_positive_id(ca_id, "ca_id")
    serial = _validate_serial(serial)
    identity = _validate_identity(identity)
    public_key_fingerprint = _validate_text(
        public_key_fingerprint,
        "public key fingerprint",
    )
    principals = _validate_principals(principals)
    if (
        isinstance(valid_after, bool)
        or isinstance(valid_before, bool)
        or not isinstance(valid_after, int)
        or not isinstance(valid_before, int)
        or valid_before - valid_after != ORDINARY_CERTIFICATE_LIFETIME
    ):
        raise StateError("certificate validity interval is not 25 hours")
    request_id = _validate_text(request_id, "request id")
    outcome = _validate_outcome(outcome)
    encoded_principals = json.dumps(list(principals), separators=(",", ":"))
    return (
        ca_id,
        serial,
        identity,
        public_key_fingerprint,
        principals,
        valid_after,
        valid_before,
        request_id,
        outcome,
        encoded_principals,
    )


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
                        (2,),
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
                        (3,),
                    )
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
                row = (3,)
            if row[0] == 3:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    StateDatabase._create_ca_tables(connection)
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
            StateDatabase._create_ca_tables(connection)
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

    @staticmethod
    def _create_ca_tables(connection: sqlite3.Connection) -> None:
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

    def register_active_ca(
        self,
        *,
        public_key: bytes,
        fingerprint: str,
        private_key_path: Path,
        activated_at: int | float | datetime | None = None,
    ) -> CAKeyRecord:
        """Register one validated active Ed25519 CA without private material."""
        key = self._validate_ca_public_key(public_key, fingerprint)
        path = self._validate_private_key_path(private_key_path)
        timestamp = _timestamp(activated_at)
        try:
            with self.transaction() as connection:
                cursor = connection.execute(
                    "INSERT INTO ca_keys "
                    "(algorithm, public_key, fingerprint, private_key_path, "
                    "activated_at, status) VALUES (?, ?, ?, ?, ?, 'active')",
                    (
                        key.get_algorithm(),
                        key.export_public_key(),
                        fingerprint,
                        str(path),
                        timestamp,
                    ),
                )
                ca_id = cursor.lastrowid
        except sqlite3.IntegrityError as exc:
            raise StateError("an active CA is already registered") from exc
        if ca_id is None:
            raise StateError("active CA registration did not return an id")
        return CAKeyRecord(
            ca_id=int(ca_id),
            algorithm=key.get_algorithm(),
            public_key=key.export_public_key(),
            fingerprint=fingerprint,
            private_key_path=path,
            activated_at=timestamp,
            status="active",
        )

    def initialize_active_ca(
        self,
        *,
        public_key: bytes,
        fingerprint: str,
        private_key_path: Path,
        request_id: str,
        activated_at: int | float | datetime | None = None,
    ) -> CAKeyRecord:
        """Commit one active CA and its initialization event as one unit."""
        key = self._validate_ca_public_key(public_key, fingerprint)
        path = self._validate_private_key_path(private_key_path)
        timestamp = _timestamp(activated_at)
        request_id = _validate_text(request_id, "request id")
        try:
            with self.transaction() as connection:
                cursor = connection.execute(
                    "INSERT INTO ca_keys "
                    "(algorithm, public_key, fingerprint, private_key_path, "
                    "activated_at, status) VALUES (?, ?, ?, ?, ?, 'active')",
                    (
                        key.get_algorithm(),
                        key.export_public_key(),
                        fingerprint,
                        str(path),
                        timestamp,
                    ),
                )
                ca_id = cursor.lastrowid
                if ca_id is None:
                    raise StateError("active CA registration did not return an id")
                connection.execute(
                    "INSERT INTO events "
                    "(occurred_at, kind, decision, request_id, ca_id) "
                    "VALUES (?, 'ca_initialized', 'allow', ?, ?)",
                    (timestamp, request_id, ca_id),
                )
        except sqlite3.IntegrityError as exc:
            raise StateError("an active CA is already registered") from exc
        return CAKeyRecord(
            ca_id=int(ca_id),
            algorithm=key.get_algorithm(),
            public_key=key.export_public_key(),
            fingerprint=fingerprint,
            private_key_path=path,
            activated_at=timestamp,
            status="active",
        )

    def get_active_ca(self) -> CAKeyRecord | None:
        """Return the validated active public CA record, if one exists."""
        row = self._connection.execute(
            "SELECT ca_id, algorithm, public_key, fingerprint, private_key_path, "
            "activated_at, status FROM ca_keys WHERE status = 'active'",
        ).fetchone()
        if row is None:
            return None
        return self._ca_record_from_row(row)

    def list_ca_keys(self) -> tuple[CAKeyRecord, ...]:
        """Return all validated CA records in stable activation order."""
        rows = self._connection.execute(
            "SELECT ca_id, algorithm, public_key, fingerprint, private_key_path, "
            "activated_at, status FROM ca_keys ORDER BY activated_at, ca_id",
        ).fetchall()
        return tuple(self._ca_record_from_row(row) for row in rows)

    def record_certificate(
        self,
        *,
        ca_id: int,
        serial: int,
        identity: str,
        public_key_fingerprint: str,
        principals: tuple[str, ...],
        valid_after: int,
        valid_before: int,
        request_id: str,
        outcome: str,
    ) -> CertificateRecord:
        """Append one safe certificate issuance record."""
        (
            ca_id,
            serial,
            identity,
            public_key_fingerprint,
            principals,
            valid_after,
            valid_before,
            request_id,
            outcome,
            encoded_principals,
        ) = _validated_certificate_fields(
            ca_id=ca_id,
            serial=serial,
            identity=identity,
            public_key_fingerprint=public_key_fingerprint,
            principals=principals,
            valid_after=valid_after,
            valid_before=valid_before,
            request_id=request_id,
            outcome=outcome,
        )
        try:
            with self.transaction() as connection:
                cursor = connection.execute(
                    "INSERT INTO certificates "
                    "(ca_id, serial, identity, public_key_fingerprint, principals, "
                    "valid_after, valid_before, request_id, outcome) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        ca_id,
                        str(serial),
                        identity,
                        public_key_fingerprint,
                        encoded_principals,
                        valid_after,
                        valid_before,
                        request_id,
                        outcome,
                    ),
                )
                certificate_id = cursor.lastrowid
        except sqlite3.IntegrityError as exc:
            raise StateError("certificate serial is already recorded") from exc
        if certificate_id is None:
            raise StateError("certificate record did not return an id")
        return CertificateRecord(
            certificate_id=int(certificate_id),
            ca_id=ca_id,
            serial=serial,
            identity=identity,
            public_key_fingerprint=public_key_fingerprint,
            principals=principals,
            valid_after=valid_after,
            valid_before=valid_before,
            request_id=request_id,
            outcome=outcome,
        )

    def list_certificates(self) -> tuple[CertificateRecord, ...]:
        """Return validated certificate metadata in insertion order."""
        rows = self._connection.execute(
            "SELECT certificate_id, ca_id, serial, identity, "
            "public_key_fingerprint, principals, valid_after, valid_before, "
            "request_id, outcome FROM certificates ORDER BY certificate_id",
        ).fetchall()
        return tuple(self._certificate_record_from_row(row) for row in rows)

    def record_certificate_with_event(
        self,
        *,
        ca_id: int,
        serial: int,
        identity: str,
        public_key_fingerprint: str,
        principals: tuple[str, ...],
        valid_after: int,
        valid_before: int,
        request_id: str,
    ) -> CertificateRecord:
        """Commit one successful certificate record and event atomically."""
        (
            ca_id,
            serial,
            identity,
            public_key_fingerprint,
            principals,
            valid_after,
            valid_before,
            request_id,
            outcome,
            encoded_principals,
        ) = _validated_certificate_fields(
            ca_id=ca_id,
            serial=serial,
            identity=identity,
            public_key_fingerprint=public_key_fingerprint,
            principals=principals,
            valid_after=valid_after,
            valid_before=valid_before,
            request_id=request_id,
            outcome="success",
        )
        try:
            with self.transaction() as connection:
                cursor = connection.execute(
                    "INSERT INTO certificates "
                    "(ca_id, serial, identity, public_key_fingerprint, principals, "
                    "valid_after, valid_before, request_id, outcome) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        ca_id,
                        str(serial),
                        identity,
                        public_key_fingerprint,
                        encoded_principals,
                        valid_after,
                        valid_before,
                        request_id,
                        outcome,
                    ),
                )
                certificate_id = cursor.lastrowid
                if certificate_id is None:
                    raise StateError("certificate record did not return an id")
                connection.execute(
                    "INSERT INTO events "
                    "(occurred_at, kind, decision, request_id, identity, "
                    "ca_id, serial) "
                    "VALUES (?, 'certificate_issued', 'allow', ?, ?, ?, ?)",
                    (
                        valid_after,
                        request_id,
                        identity,
                        ca_id,
                        str(serial),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise StateError("certificate serial is already recorded") from exc
        return CertificateRecord(
            certificate_id=int(certificate_id),
            ca_id=ca_id,
            serial=serial,
            identity=identity,
            public_key_fingerprint=public_key_fingerprint,
            principals=principals,
            valid_after=valid_after,
            valid_before=valid_before,
            request_id=request_id,
            outcome=outcome,
        )

    def record_event(
        self,
        *,
        kind: str,
        decision: str,
        request_id: str,
        occurred_at: int | float | datetime | None = None,
        identity: str | None = None,
        ca_id: int | None = None,
        serial: int | None = None,
    ) -> EventRecord:
        """Append one validated, secret-free CA event."""
        kind = _validate_text(kind, "event kind")
        decision = _validate_text(decision, "event decision")
        request_id = _validate_text(request_id, "request id")
        if identity is not None:
            identity = _validate_identity(identity)
        if ca_id is not None:
            _validate_positive_id(ca_id, "ca_id")
        if serial is not None:
            serial = _validate_serial(serial)
        timestamp = _timestamp(occurred_at)
        try:
            with self.transaction() as connection:
                cursor = connection.execute(
                    "INSERT INTO events "
                    "(occurred_at, kind, decision, request_id, identity, "
                    "ca_id, serial) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        timestamp,
                        kind,
                        decision,
                        request_id,
                        identity,
                        ca_id,
                        None if serial is None else str(serial),
                    ),
                )
                event_id = cursor.lastrowid
        except sqlite3.IntegrityError as exc:
            raise StateError("event could not be recorded") from exc
        if event_id is None:
            raise StateError("event record did not return an id")
        return EventRecord(
            event_id=int(event_id),
            occurred_at=timestamp,
            kind=kind,
            decision=decision,
            request_id=request_id,
            identity=identity,
            ca_id=ca_id,
            serial=serial,
        )

    def list_events(self) -> tuple[EventRecord, ...]:
        """Return validated append-only events in stable insertion order."""
        rows = self._connection.execute(
            "SELECT event_id, occurred_at, kind, decision, request_id, identity, "
            "ca_id, serial FROM events ORDER BY event_id",
        ).fetchall()
        return tuple(self._event_record_from_row(row) for row in rows)

    def verify_ca_state(self) -> None:
        """Verify SQLite integrity and all persisted CA/certificate relationships."""
        try:
            integrity = self._connection.execute("PRAGMA integrity_check").fetchone()
        except sqlite3.DatabaseError as exc:
            raise StateError("SQLite integrity is unavailable") from exc
        if integrity != ("ok",):
            raise StateError("SQLite integrity check failed")
        ca_records = self.list_ca_keys()
        ca_ids = {record.ca_id for record in ca_records}
        if sum(record.status == "active" for record in ca_records) > 1:
            raise StateError("multiple active CA records exist")
        certificates = self.list_certificates()
        certificate_keys = {
            (record.ca_id, record.serial, record.request_id, record.identity)
            for record in certificates
        }
        events = self.list_events()
        for event in events:
            if event.ca_id is not None and event.ca_id not in ca_ids:
                raise StateError("event references an unknown CA")
            if event.serial is not None:
                if event.ca_id is None or not any(
                    certificate.ca_id == event.ca_id
                    and certificate.serial == event.serial
                    for certificate in certificates
                ):
                    raise StateError("event references an unknown certificate")
        for certificate in certificates:
            if certificate.ca_id not in ca_ids:
                raise StateError("certificate references an unknown CA")
            if certificate.outcome == "success" and not any(
                event.kind == "certificate_issued"
                and event.decision == "allow"
                and event.ca_id == certificate.ca_id
                and event.serial == certificate.serial
                and event.request_id == certificate.request_id
                and event.identity == certificate.identity
                for event in events
            ):
                raise StateError("certificate success event is missing")
        if len(certificate_keys) != len(certificates):
            raise StateError("duplicate certificate state exists")

    @staticmethod
    def _validate_ca_public_key(public_key: bytes, fingerprint: str) -> asyncssh.SSHKey:
        if not isinstance(public_key, bytes) or not public_key:
            raise StateError("CA public key is malformed")
        if not isinstance(fingerprint, str) or not fingerprint:
            raise StateError("CA fingerprint is malformed")
        try:
            key = asyncssh.import_public_key(public_key)
        except Exception as exc:
            raise StateError("CA public key is invalid") from exc
        if key.get_algorithm() != "ssh-ed25519":
            raise StateError("CA algorithm is unsupported")
        if key.get_fingerprint() != fingerprint:
            raise StateError("CA fingerprint does not match public key")
        return key

    @staticmethod
    def _validate_private_key_path(private_key_path: Path) -> Path:
        if not isinstance(private_key_path, Path):
            private_key_path = Path(private_key_path)
        if private_key_path.name in {"", ".", ".."}:
            raise StateError("CA private-key path is malformed")
        return private_key_path

    @staticmethod
    def _ca_record_from_row(row: tuple[object, ...]) -> CAKeyRecord:
        (
            ca_id,
            algorithm,
            public_key,
            fingerprint,
            private_key_path,
            activated_at,
            status,
        ) = row
        if not isinstance(ca_id, int) or ca_id <= 0:
            raise StateError("CA record id is malformed")
        if not isinstance(algorithm, str) or algorithm != "ssh-ed25519":
            raise StateError("CA record algorithm is unsupported")
        if not isinstance(public_key, (bytes, bytearray)):
            raise StateError("CA record public key is malformed")
        if not isinstance(fingerprint, str) or not isinstance(private_key_path, str):
            raise StateError("CA record metadata is malformed")
        if not isinstance(activated_at, int) or activated_at < 0:
            raise StateError("CA activation time is malformed")
        if status not in {"active", "retired"}:
            raise StateError("CA record status is malformed")
        key = StateDatabase._validate_ca_public_key(bytes(public_key), fingerprint)
        return CAKeyRecord(
            ca_id=ca_id,
            algorithm=algorithm,
            public_key=key.export_public_key(),
            fingerprint=fingerprint,
            private_key_path=StateDatabase._validate_private_key_path(
                Path(private_key_path),
            ),
            activated_at=activated_at,
            status=cast(str, status),
        )

    @staticmethod
    def _certificate_record_from_row(row: tuple[object, ...]) -> CertificateRecord:
        (
            certificate_id,
            ca_id,
            serial,
            identity,
            public_key_fingerprint,
            principals,
            valid_after,
            valid_before,
            request_id,
            outcome,
        ) = row
        if not isinstance(certificate_id, int) or certificate_id <= 0:
            raise StateError("certificate id is malformed")
        _validate_positive_id(ca_id, "ca_id")
        if not isinstance(serial, str):
            raise StateError("certificate serial is malformed")
        try:
            serial_number = _validate_serial(int(serial))
        except (TypeError, ValueError) as exc:
            raise StateError("certificate serial is malformed") from exc
        identity = _validate_identity(identity)
        public_key_fingerprint = _validate_text(
            public_key_fingerprint,
            "public key fingerprint",
        )
        try:
            principal_values = tuple(json.loads(cast(str, principals)))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise StateError("certificate principals are malformed") from exc
        principal_values = _validate_principals(principal_values)
        if not isinstance(valid_after, int) or not isinstance(valid_before, int):
            raise StateError("certificate validity is malformed")
        if valid_before - valid_after != ORDINARY_CERTIFICATE_LIFETIME:
            raise StateError("certificate validity interval is not 25 hours")
        request_id = _validate_text(request_id, "request id")
        outcome = _validate_outcome(outcome)
        return CertificateRecord(
            certificate_id=certificate_id,
            ca_id=cast(int, ca_id),
            serial=serial_number,
            identity=identity,
            public_key_fingerprint=public_key_fingerprint,
            principals=principal_values,
            valid_after=valid_after,
            valid_before=valid_before,
            request_id=request_id,
            outcome=outcome,
        )

    @staticmethod
    def _event_record_from_row(row: tuple[object, ...]) -> EventRecord:
        event_id, occurred_at, kind, decision, request_id, identity, ca_id, serial = row
        if not isinstance(event_id, int) or event_id <= 0:
            raise StateError("event id is malformed")
        if not isinstance(occurred_at, int) or occurred_at < 0:
            raise StateError("event time is malformed")
        kind = _validate_text(kind, "event kind")
        decision = _validate_text(decision, "event decision")
        request_id = _validate_text(request_id, "request id")
        if identity is not None:
            identity = _validate_identity(identity)
        if ca_id is not None:
            _validate_positive_id(ca_id, "ca_id")
        serial_number = None
        if serial is not None:
            if not isinstance(serial, str):
                raise StateError("event serial is malformed")
            try:
                serial_number = _validate_serial(int(serial))
            except (TypeError, ValueError) as exc:
                raise StateError("event serial is malformed") from exc
        return EventRecord(
            event_id=event_id,
            occurred_at=occurred_at,
            kind=kind,
            decision=decision,
            request_id=request_id,
            identity=identity,
            ca_id=cast(int | None, ca_id),
            serial=serial_number,
        )

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
