"""SQLite persistence operations for CA, certificate, and audit records."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def insert_ca(database: Any, values: Mapping[str, Any]) -> int | None:
    with database.transaction() as connection:
        cursor = connection.execute(
            "INSERT INTO ca_keys "
            "(algorithm, public_key, fingerprint, private_key_path, "
            "activated_at, status) VALUES (?, ?, ?, ?, ?, 'active')",
            (
                values["algorithm"],
                values["public_key"],
                values["fingerprint"],
                values["private_key_path"],
                values["activated_at"],
            ),
        )
        return cursor.lastrowid


def insert_ca_with_event(database: Any, values: Mapping[str, Any]) -> int | None:
    with database.transaction() as connection:
        cursor = connection.execute(
            "INSERT INTO ca_keys "
            "(algorithm, public_key, fingerprint, private_key_path, "
            "activated_at, status) VALUES (?, ?, ?, ?, ?, 'active')",
            (
                values["algorithm"],
                values["public_key"],
                values["fingerprint"],
                values["private_key_path"],
                values["activated_at"],
            ),
        )
        ca_id = cursor.lastrowid
        if ca_id is not None:
            connection.execute(
                "INSERT INTO events "
                "(occurred_at, kind, decision, request_id, ca_id) "
                "VALUES (?, 'ca_initialized', 'allow', ?, ?)",
                (values["activated_at"], values["request_id"], ca_id),
            )
        return ca_id


def active_ca_row(database: Any) -> tuple[Any, ...] | None:
    with database.read_connection() as connection:
        row = connection.execute(
            "SELECT ca_id, algorithm, public_key, fingerprint, private_key_path, "
            "activated_at, status FROM ca_keys WHERE status = 'active'",
        ).fetchone()
    return None if row is None else tuple(row)


def ca_rows(database: Any) -> list[tuple[Any, ...]]:
    with database.read_connection() as connection:
        return [
            tuple(row)
            for row in connection.execute(
                "SELECT ca_id, algorithm, public_key, fingerprint, private_key_path, "
                "activated_at, status FROM ca_keys ORDER BY activated_at, ca_id",
            ).fetchall()
        ]


def insert_certificate(database: Any, values: Mapping[str, Any]) -> int | None:
    with database.transaction() as connection:
        cursor = connection.execute(
            "INSERT INTO certificates "
            "(ca_id, serial, identity, public_key_fingerprint, principals, "
            "valid_after, valid_before, request_id, outcome) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                values["ca_id"],
                str(values["serial"]),
                values["identity"],
                values["public_key_fingerprint"],
                values["encoded_principals"],
                values["valid_after"],
                values["valid_before"],
                values["request_id"],
                values["outcome"],
            ),
        )
        if values.get("record_event"):
            connection.execute(
                "INSERT INTO events "
                "(occurred_at, kind, decision, request_id, identity, "
                "ca_id, serial) VALUES (?, 'certificate_issued', 'allow', ?, ?, ?, ?)",
                (
                    values["valid_after"],
                    values["request_id"],
                    values["identity"],
                    values["ca_id"],
                    str(values["serial"]),
                ),
            )
        return cursor.lastrowid


def certificate_rows(database: Any) -> list[tuple[Any, ...]]:
    with database.read_connection() as connection:
        return [
            tuple(row)
            for row in connection.execute(
                "SELECT certificate_id, ca_id, serial, identity, "
                "public_key_fingerprint, principals, valid_after, valid_before, "
                "request_id, outcome FROM certificates ORDER BY certificate_id",
            ).fetchall()
        ]


def insert_event(database: Any, values: Mapping[str, Any]) -> int | None:
    with database.transaction() as connection:
        cursor = connection.execute(
            "INSERT INTO events "
            "(occurred_at, kind, decision, request_id, identity, ca_id, serial) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                values["occurred_at"],
                values["kind"],
                values["decision"],
                values["request_id"],
                values["identity"],
                values["ca_id"],
                values["serial"],
            ),
        )
        return cursor.lastrowid


def event_rows(
    database: Any,
    *,
    serial: int | None = None,
    identity: str | None = None,
    kind: str | None = None,
    from_time: int | None = None,
    to_time: int | None = None,
    limit: int | None = None,
) -> list[tuple[Any, ...]]:
    clauses: list[str] = []
    parameters: list[Any] = []
    if serial is not None:
        clauses.append("serial = ?")
        parameters.append(str(serial))
    if identity is not None:
        clauses.append("identity = ?")
        parameters.append(identity)
    if kind is not None:
        clauses.append("kind = ?")
        parameters.append(kind)
    if from_time is not None:
        clauses.append("occurred_at >= ?")
        parameters.append(from_time)
    if to_time is not None:
        clauses.append("occurred_at <= ?")
        parameters.append(to_time)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    limit_clause = " LIMIT ?" if limit is not None else ""
    if limit is not None:
        parameters.append(limit)
    with database.read_connection() as connection:
        return [
            tuple(row)
            for row in connection.execute(
                "SELECT event_id, occurred_at, kind, decision, request_id, identity, "
                f"ca_id, serial FROM events{where} ORDER BY event_id{limit_clause}",
                parameters,
            ).fetchall()
        ]
