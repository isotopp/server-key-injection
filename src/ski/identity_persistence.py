"""SQLite persistence adapter for demo identity and group rows."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ski.state import StateDatabase


class SqliteIdentityRepository:
    """Keep identity SQL behind the public state unit-of-work boundary."""

    def __init__(self, database: StateDatabase) -> None:
        self._database = database

    @property
    def schema_version(self) -> int:
        return self._database.schema_version

    @property
    def table_names(self) -> frozenset[str]:
        return self._database.table_names

    def user_row(self, username: str) -> tuple[Any, ...] | None:
        with self._database.read_connection() as connection:
            row = connection.execute(
                "SELECT username, password_verifier, totp_secret, enabled "
                "FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        return None if row is None else tuple(row)

    def user_rows(self) -> list[tuple[Any, ...]]:
        with self._database.read_connection() as connection:
            return [
                tuple(row)
                for row in connection.execute(
                    "SELECT username, enabled FROM users ORDER BY username",
                ).fetchall()
            ]

    def insert_user(
        self,
        username: str,
        verifier: str,
        totp_secret: str,
    ) -> None:
        with self._database.transaction() as connection:
            connection.execute(
                "INSERT INTO users "
                "(username, password_verifier, totp_secret, enabled) "
                "VALUES (?, ?, ?, 1)",
                (username, verifier, totp_secret),
            )

    def update_user(
        self,
        username: str,
        assignment: str,
        values: Sequence[Any],
    ) -> None:
        with self._database.transaction() as connection:
            if (
                connection.execute(
                    "SELECT 1 FROM users WHERE username = ?", (username,)
                ).fetchone()
                is None
            ):
                return
            connection.execute(
                f"UPDATE users SET {assignment} WHERE username = ?",
                (*values, username),
            )

    def group_rows(self) -> list[tuple[Any, ...]]:
        with self._database.read_connection() as connection:
            return [
                tuple(row)
                for row in connection.execute(
                    "SELECT name FROM groups ORDER BY name",
                ).fetchall()
            ]

    def group_exists(self, name: str) -> bool:
        with self._database.read_connection() as connection:
            return (
                connection.execute(
                    "SELECT 1 FROM groups WHERE name = ?", (name,)
                ).fetchone()
                is not None
            )

    def group_membership_rows(self, name: str) -> list[tuple[Any, ...]]:
        with self._database.read_connection() as connection:
            return [
                tuple(row)
                for row in connection.execute(
                    "SELECT username FROM user_groups "
                    "WHERE group_name = ? ORDER BY username",
                    (name,),
                ).fetchall()
            ]

    def user_group_rows(self, username: str) -> list[tuple[Any, ...]]:
        with self._database.read_connection() as connection:
            return [
                tuple(row)
                for row in connection.execute(
                    "SELECT group_name FROM user_groups "
                    "WHERE username = ? ORDER BY group_name",
                    (username,),
                ).fetchall()
            ]

    def create_group(self, name: str) -> None:
        with self._database.transaction() as connection:
            connection.execute("INSERT INTO groups (name) VALUES (?)", (name,))

    def remove_group(self, name: str) -> bool:
        with self._database.transaction() as connection:
            membership = connection.execute(
                "SELECT 1 FROM user_groups WHERE group_name = ? LIMIT 1",
                (name,),
            ).fetchone()
            if membership is not None:
                return False
            result = connection.execute(
                "DELETE FROM groups WHERE name = ?",
                (name,),
            )
            return result.rowcount == 1

    def change_membership(self, group: str, username: str, *, add: bool) -> bool:
        with self._database.transaction() as connection:
            if (
                connection.execute(
                    "SELECT 1 FROM groups WHERE name = ?", (group,)
                ).fetchone()
                is None
            ):
                return False
            if (
                connection.execute(
                    "SELECT 1 FROM users WHERE username = ?", (username,)
                ).fetchone()
                is None
            ):
                return False
            if add:
                connection.execute(
                    "INSERT INTO user_groups (username, group_name) VALUES (?, ?)",
                    (username, group),
                )
                return True
            result = connection.execute(
                "DELETE FROM user_groups WHERE username = ? AND group_name = ?",
                (username, group),
            )
            return result.rowcount == 1
