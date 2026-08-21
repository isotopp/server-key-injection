"""Application workflows for read-only CA inspection commands."""

from __future__ import annotations

import re
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from ski.ca import CAFileError, CAFileWriter
from ski.configuration import ConfigurationError, load_runtime_configuration
from ski.policy import PolicyValidationError, validate_username
from ski.state import CAKeyRecord, EventRecord, StateDatabase


def _ca_configuration():
    """Load the complete CA configuration required by CA workflows."""
    configuration = load_runtime_configuration(bind="127.0.0.1", port=22)
    if (
        configuration.ca_private_key is None
        or configuration.ca_public_key is None
        or configuration.ca_krl is None
    ):
        raise ConfigurationError("ordinary CA configuration is incomplete")
    return configuration


@contextmanager
def ca_read_database() -> Iterator[StateDatabase]:
    """Open and always close the configured CA database for one read."""
    configuration = _ca_configuration()
    database = StateDatabase.open(configuration.database)
    try:
        yield database
    finally:
        database.close()


def initialize_ca() -> CAKeyRecord:
    """Install CA files and register them with compensating cleanup."""
    configuration = _ca_configuration()
    assert configuration.ca_private_key is not None
    assert configuration.ca_public_key is not None
    assert configuration.ca_krl is not None
    paths: tuple[Path, ...] = (
        configuration.ca_private_key,
        configuration.ca_public_key,
        configuration.ca_krl,
    )
    database = StateDatabase.open(configuration.database)
    try:
        if database.get_active_ca() is not None:
            raise CAFileError("an active CA is already registered")
        material = CAFileWriter().install(
            private_path=configuration.ca_private_key,
            public_path=configuration.ca_public_key,
            krl_path=configuration.ca_krl,
        )
        try:
            return database.initialize_active_ca(
                public_key=material.public_bytes,
                fingerprint=material.fingerprint,
                private_key_path=configuration.ca_private_key,
                request_id=f"ca-init-{secrets.token_hex(16)}",
            )
        except Exception:
            _remove_initialized_files(paths)
            raise
    finally:
        database.close()


def _remove_initialized_files(paths: tuple[Path, ...]) -> None:
    """Remove only fresh CA targets after a failed database commit."""
    for path in paths:
        path.unlink(missing_ok=True)


def show_ca_records(*, show_all: bool) -> tuple[CAKeyRecord, ...]:
    """Return redacted CA records for the requested public view."""
    with ca_read_database() as database:
        if show_all:
            return database.list_ca_keys()
        active = database.get_active_ca()
        return () if active is None else (active,)


def read_ca_public_key(*, fingerprint: str | None) -> str | None:
    """Return one selected CA public key without private metadata."""
    with ca_read_database() as database:
        records = database.list_ca_keys()
        selected = (
            next((ca for ca in records if ca.fingerprint == fingerprint), None)
            if fingerprint is not None
            else database.get_active_ca()
        )
        return (
            None if selected is None else selected.public_key.decode("utf-8").rstrip()
        )


def _parse_log_serial(value: str | None) -> int | None:
    if value is None:
        return None
    if not value.isascii() or not value.isdigit():
        raise ValueError("serial filter is malformed")
    serial = int(value)
    if serial >= 2**64:
        raise ValueError("serial filter is malformed")
    return serial


def _parse_log_time(value: str | None) -> int | None:
    if value is None:
        return None
    if value.isascii() and value.isdigit():
        return int(value)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("time filter is malformed") from exc
    if parsed.tzinfo is None:
        raise ValueError("time filter must include a timezone")
    timestamp = int(parsed.astimezone(UTC).timestamp())
    if timestamp < 0:
        raise ValueError("time filter is malformed")
    return timestamp


def list_ca_events(
    *,
    serial: str | None,
    user: str | None,
    event: str | None,
    from_time: str | None,
    to_time: str | None,
) -> tuple[str, ...]:
    """Return bounded, strictly filtered, redacted CA event lines."""
    serial_value = _parse_log_serial(serial)
    if user is not None:
        try:
            validate_username(user)
        except PolicyValidationError as exc:
            raise ValueError("user filter is malformed") from exc
    if event is not None and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", event) is None:
        raise ValueError("event filter is malformed")
    from_value = _parse_log_time(from_time)
    to_value = _parse_log_time(to_time)
    if from_value is not None and to_value is not None and from_value > to_value:
        raise ValueError("time filter range is malformed")
    with ca_read_database() as database:
        events = database.list_events(
            serial=serial_value,
            identity=user,
            kind=event,
            from_time=from_value,
            to_time=to_value,
            limit=100,
        )
        return tuple(_render_event(record) for record in events)


def _render_event(record: EventRecord) -> str:
    """Render only fixed safe event fields."""
    fields = [
        str(record.event_id),
        str(record.occurred_at),
        record.kind,
        record.decision,
        f"request={record.request_id}",
    ]
    if record.identity is not None:
        fields.append(f"user={record.identity}")
    if record.serial is not None:
        fields.append(f"serial={record.serial}")
    return " ".join(fields)


def verify_ca_state() -> None:
    """Verify CA state without mutating the database or notifying the daemon."""
    with ca_read_database() as database:
        database.verify_ca_state()
