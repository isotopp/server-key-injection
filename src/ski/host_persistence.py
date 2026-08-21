"""SQLite persistence operations for the issuer host key."""

from __future__ import annotations

from typing import Any


def load_host_key_row(database: Any) -> tuple[Any, ...] | None:
    """Read the stored host-key row through the database query boundary."""
    with database.read_connection() as connection:
        row = connection.execute(
            "SELECT algorithm, private_key, public_key, fingerprint "
            "FROM ssh_host_keys WHERE singleton = 1",
        ).fetchone()
    return None if row is None else tuple(row)


def insert_host_key(database: Any, material: Any) -> None:
    """Persist validated host-key material in one transaction."""
    with database.transaction() as connection:
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
