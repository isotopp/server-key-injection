"""Replaceable identity storage contracts and the SQLite demo implementation."""

from __future__ import annotations

import sqlite3
from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from ski.policy import (
    PolicyValidationError,
)
from ski.policy import (
    validate_group_name as _validate_group_name,
)
from ski.policy import (
    validate_username as _validate_username,
)
from ski.state import StateDatabase


class IdentityStoreError(RuntimeError):
    """Base error for identity data or identity-store operations."""


class IdentityValidationError(IdentityStoreError):
    """Raised when a caller or persisted identity value is malformed."""


class IdentityAlreadyExistsError(IdentityStoreError):
    """Raised when a unique identity or group already exists."""


class IdentityNotFoundError(IdentityStoreError):
    """Raised when the requested identity or group is absent."""


class IdentityDisabledError(IdentityStoreError):
    """Raised when a disabled identity cannot be used for authentication."""


class IdentityDataError(IdentityStoreError):
    """Raised when persisted identity data fails validation."""


class IdentityUnavailableError(IdentityStoreError):
    """Raised when the identity backend cannot answer a request."""


@dataclass(frozen=True, slots=True)
class IdentitySnapshot:
    """Stable, non-secret identity data bound to one request."""

    username: str
    groups: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class UserRecord:
    """Validated user data, including credentials for internal operations."""

    username: str
    password_verifier: str
    totp_secret: str
    enabled: bool
    groups: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class UserSummary:
    """Non-secret user data suitable for administrative display."""

    username: str
    enabled: bool


class IdentityStore(ABC):
    """Backend-neutral identity and group operations used by the issuer."""

    @abstractmethod
    def get_user(self, username: str) -> UserRecord:
        """Return one validated user record."""

    @abstractmethod
    def get_group_snapshot(self, username: str) -> IdentitySnapshot:
        """Return the current enabled identity and canonical group snapshot."""

    @abstractmethod
    def create_user(self, username: str, password: str, totp_secret: str) -> UserRecord:
        """Create one enabled user and hash its password."""

    @abstractmethod
    def list_users(self) -> tuple[UserSummary, ...]:
        """Return validated non-secret user summaries."""

    @abstractmethod
    def set_user_enabled(self, username: str, enabled: bool) -> UserRecord:
        """Change only the enabled state of one user."""

    @abstractmethod
    def replace_password(self, username: str, password: str) -> UserRecord:
        """Replace one user's password verifier."""

    @abstractmethod
    def replace_totp_secret(self, username: str, totp_secret: str) -> UserRecord:
        """Replace one user's TOTP secret."""

    @abstractmethod
    def verify_password(self, username: str, password: str) -> bool:
        """Verify a password without disclosing identity-store details."""

    @abstractmethod
    def verify_totp(self, username: str, code: str, *, now: int | None = None) -> bool:
        """Verify a TOTP code using the backend's configured policy."""

    @abstractmethod
    def create_group(self, name: str) -> None:
        """Create one canonical group."""

    @abstractmethod
    def list_groups(self) -> tuple[str, ...]:
        """Return canonical group names in stable order."""

    @abstractmethod
    def get_group_members(self, name: str) -> tuple[str, ...]:
        """Return one group's canonical member names in stable order."""

    @abstractmethod
    def remove_group(self, name: str) -> None:
        """Remove an empty canonical group."""

    @abstractmethod
    def add_membership(self, group: str, username: str) -> None:
        """Add one user/group membership."""

    @abstractmethod
    def remove_membership(self, group: str, username: str) -> None:
        """Remove one user/group membership."""


def validate_username(username: str) -> str:
    """Validate one already-canonical ASCII username."""
    try:
        return _validate_username(username)
    except PolicyValidationError as exc:
        raise IdentityValidationError("username is not canonical") from exc


def validate_group_name(name: str) -> str:
    """Validate one already-canonical ASCII group name."""
    try:
        return _validate_group_name(name)
    except PolicyValidationError as exc:
        raise IdentityValidationError("group name is not canonical") from exc


class SqliteIdentityStore(IdentityStore):
    """Store demo identities in the SQLite database owned by the service."""

    def __init__(
        self,
        database: StateDatabase,
        *,
        password_hasher: PasswordHasher | None = None,
        totp_verifier: Callable[..., bool] | None = None,
    ) -> None:
        self._database = database
        self._password_hasher = (
            PasswordHasher() if password_hasher is None else password_hasher
        )
        self._totp_verifier = totp_verifier
        if database.schema_version != 4:
            raise IdentityUnavailableError("identity schema is unavailable")

    @property
    def schema_version(self) -> int:
        """Return the schema version exposed by this identity backend."""
        return self._database.schema_version

    @property
    def table_names(self) -> frozenset[str]:
        """Return the application's current table names."""
        return self._database.table_names

    def get_user(self, username: str) -> UserRecord:
        username = validate_username(username)
        try:
            with self._database.read_connection() as connection:
                row = connection.execute(
                    "SELECT username, password_verifier, totp_secret, enabled "
                    "FROM users WHERE username = ?",
                    (username,),
                ).fetchone()
            if row is None:
                raise IdentityNotFoundError("user is not available")
            return self._record_from_row(row)
        except IdentityStoreError:
            raise
        except Exception as exc:
            raise IdentityUnavailableError("identity data is unavailable") from exc

    def get_group_snapshot(self, username: str) -> IdentitySnapshot:
        user = self.get_user(username)
        if not user.enabled:
            raise IdentityDisabledError("user is disabled")
        return IdentitySnapshot(username=user.username, groups=user.groups)

    def create_user(self, username: str, password: str, totp_secret: str) -> UserRecord:
        username = validate_username(username)
        if not isinstance(password, str) or not password:
            raise IdentityValidationError("password is malformed")
        totp_secret = self._validate_totp_secret(totp_secret)
        try:
            verifier = self._password_hasher.hash(password)
            with self._database.transaction() as connection:
                connection.execute(
                    "INSERT INTO users "
                    "(username, password_verifier, totp_secret, enabled) "
                    "VALUES (?, ?, ?, 1)",
                    (username, verifier, totp_secret),
                )
        except IdentityStoreError:
            raise
        except Exception as exc:
            if isinstance(exc, sqlite3.IntegrityError):
                raise IdentityAlreadyExistsError("user already exists") from exc
            raise IdentityUnavailableError("identity data is unavailable") from exc
        return self.get_user(username)

    def list_users(self) -> tuple[UserSummary, ...]:
        try:
            with self._database.read_connection() as connection:
                rows = connection.execute(
                    "SELECT username, enabled FROM users ORDER BY username",
                ).fetchall()
            summaries: list[UserSummary] = []
            for username, enabled in rows:
                validate_username(username)
                summaries.append(
                    UserSummary(
                        username=username, enabled=self._validate_enabled(enabled)
                    ),
                )
            return tuple(summaries)
        except IdentityStoreError as exc:
            raise IdentityDataError("identity data is malformed") from exc
        except Exception as exc:
            raise IdentityUnavailableError("identity data is unavailable") from exc

    def set_user_enabled(self, username: str, enabled: bool) -> UserRecord:
        username = validate_username(username)
        if not isinstance(enabled, bool):
            raise IdentityValidationError("enabled state is malformed")
        self._update_user(username, "enabled = ?", (int(enabled),))
        return self.get_user(username)

    def replace_password(self, username: str, password: str) -> UserRecord:
        username = validate_username(username)
        if not isinstance(password, str) or not password:
            raise IdentityValidationError("password is malformed")
        verifier = self._password_hasher.hash(password)
        self._update_user(username, "password_verifier = ?", (verifier,))
        return self.get_user(username)

    def replace_totp_secret(self, username: str, totp_secret: str) -> UserRecord:
        username = validate_username(username)
        totp_secret = self._validate_totp_secret(totp_secret)
        self._update_user(username, "totp_secret = ?", (totp_secret,))
        return self.get_user(username)

    def verify_password(self, username: str, password: str) -> bool:
        try:
            record = self.get_user(username)
            if not record.enabled:
                return False
            verified = bool(
                self._password_hasher.verify(record.password_verifier, password)
            )
            if verified and self._password_hasher.check_needs_rehash(
                record.password_verifier,
            ):
                self._update_user(
                    username,
                    "password_verifier = ?",
                    (self._password_hasher.hash(password),),
                )
            return verified
        except (IdentityStoreError, TypeError, VerificationError, InvalidHashError):
            return False

    def verify_totp(self, username: str, code: str, *, now: int | None = None) -> bool:
        try:
            record = self.get_user(username)
            if not record.enabled or not isinstance(code, str):
                return False
            totp = pyotp.TOTP(record.totp_secret)
            if self._totp_verifier is not None:
                return bool(self._totp_verifier(totp, code, now=now))
            for_time = None if now is None else datetime.fromtimestamp(now, tz=UTC)
            return bool(totp.verify(code, valid_window=1, for_time=for_time))
        except (IdentityStoreError, ValueError, TypeError):
            return False

    def create_group(self, name: str) -> None:
        name = validate_group_name(name)
        try:
            with self._database.transaction() as connection:
                connection.execute("INSERT INTO groups (name) VALUES (?)", (name,))
        except Exception as exc:
            if isinstance(exc, sqlite3.IntegrityError):
                raise IdentityAlreadyExistsError("group already exists") from exc
            raise IdentityUnavailableError("identity data is unavailable") from exc

    def list_groups(self) -> tuple[str, ...]:
        try:
            with self._database.read_connection() as connection:
                rows = connection.execute(
                    "SELECT name FROM groups ORDER BY name",
                ).fetchall()
            names = tuple(validate_group_name(row[0]) for row in rows)
            return names
        except IdentityStoreError as exc:
            raise IdentityDataError("identity data is malformed") from exc
        except Exception as exc:
            raise IdentityUnavailableError("identity data is unavailable") from exc

    def get_group_members(self, name: str) -> tuple[str, ...]:
        name = validate_group_name(name)
        try:
            with self._database.read_connection() as connection:
                if (
                    connection.execute(
                        "SELECT 1 FROM groups WHERE name = ?", (name,)
                    ).fetchone()
                    is None
                ):
                    raise IdentityNotFoundError("group is not available")
                rows = connection.execute(
                    "SELECT username FROM user_groups "
                    "WHERE group_name = ? ORDER BY username",
                    (name,),
                ).fetchall()
            members = tuple(validate_username(row[0]) for row in rows)
            if len(set(members)) != len(members):
                raise IdentityDataError("group membership is duplicated")
            return members
        except IdentityStoreError as exc:
            if isinstance(exc, IdentityNotFoundError):
                raise
            raise IdentityDataError("identity data is malformed") from exc
        except Exception as exc:
            raise IdentityUnavailableError("identity data is unavailable") from exc

    def remove_group(self, name: str) -> None:
        name = validate_group_name(name)
        try:
            with self._database.transaction() as connection:
                membership = connection.execute(
                    "SELECT 1 FROM user_groups WHERE group_name = ? LIMIT 1",
                    (name,),
                ).fetchone()
                if membership is not None:
                    raise IdentityStoreError("group is not empty")
                result = connection.execute(
                    "DELETE FROM groups WHERE name = ?",
                    (name,),
                )
                if result.rowcount != 1:
                    raise IdentityNotFoundError("group is not available")
        except IdentityStoreError:
            raise
        except Exception as exc:
            raise IdentityUnavailableError("identity data is unavailable") from exc

    def add_membership(self, group: str, username: str) -> None:
        group = validate_group_name(group)
        username = validate_username(username)
        self._change_membership(group, username, add=True)

    def remove_membership(self, group: str, username: str) -> None:
        group = validate_group_name(group)
        username = validate_username(username)
        self._change_membership(group, username, add=False)

    def _change_membership(self, group: str, username: str, *, add: bool) -> None:
        try:
            with self._database.transaction() as connection:
                if (
                    connection.execute(
                        "SELECT 1 FROM groups WHERE name = ?", (group,)
                    ).fetchone()
                    is None
                ):
                    raise IdentityNotFoundError("group is not available")
                if (
                    connection.execute(
                        "SELECT 1 FROM users WHERE username = ?", (username,)
                    ).fetchone()
                    is None
                ):
                    raise IdentityNotFoundError("user is not available")
                if add:
                    connection.execute(
                        "INSERT INTO user_groups (username, group_name) VALUES (?, ?)",
                        (username, group),
                    )
                else:
                    result = connection.execute(
                        "DELETE FROM user_groups WHERE username = ? AND group_name = ?",
                        (username, group),
                    )
                    if result.rowcount != 1:
                        raise IdentityNotFoundError("membership is not available")
        except IdentityStoreError:
            raise
        except Exception as exc:
            if isinstance(exc, sqlite3.IntegrityError):
                raise IdentityAlreadyExistsError("membership already exists") from exc
            raise IdentityUnavailableError("identity data is unavailable") from exc

    def _update_user(
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
                raise IdentityNotFoundError("user is not available")
            connection.execute(
                f"UPDATE users SET {assignment} WHERE username = ?",
                (*values, username),
            )

    def _record_from_row(self, row: Sequence[Any]) -> UserRecord:
        username, verifier, totp_secret, enabled = row
        try:
            username = validate_username(username)
            if not isinstance(verifier, str) or not verifier:
                raise IdentityDataError("password verifier is malformed")
            totp_secret = self._validate_totp_secret(totp_secret)
            enabled = self._validate_enabled(enabled)
            groups = self._groups_for(username)
        except IdentityStoreError as exc:
            raise IdentityDataError("identity data is malformed") from exc
        return UserRecord(
            username=username,
            password_verifier=verifier,
            totp_secret=totp_secret,
            enabled=enabled,
            groups=groups,
        )

    def _groups_for(self, username: str) -> tuple[str, ...]:
        with self._database.read_connection() as connection:
            rows = connection.execute(
                "SELECT group_name FROM user_groups "
                "WHERE username = ? ORDER BY group_name",
                (username,),
            ).fetchall()
        groups: list[str] = []
        for (group_name,) in rows:
            group_name = validate_group_name(group_name)
            with self._database.read_connection() as connection:
                group_exists = connection.execute(
                    "SELECT 1 FROM groups WHERE name = ?", (group_name,)
                ).fetchone()
            if group_exists is None:
                raise IdentityDataError("group membership is malformed")
            if group_name in groups:
                raise IdentityDataError("group membership is duplicated")
            groups.append(group_name)
        return tuple(groups)

    @staticmethod
    def _validate_enabled(value: object) -> bool:
        if value not in (0, 1):
            raise IdentityDataError("enabled state is malformed")
        return bool(value)

    @staticmethod
    def _validate_totp_secret(value: object) -> str:
        if not isinstance(value, str) or not value:
            raise IdentityValidationError("TOTP secret is malformed")
        try:
            pyotp.TOTP(value)
        except (TypeError, ValueError) as exc:
            raise IdentityValidationError("TOTP secret is malformed") from exc
        return value
