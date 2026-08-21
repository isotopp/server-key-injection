"""Behavioural tests for post-mutation service reload notification."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, cast

import pytest

from ski.notify import (
    NotificationResult,
    ServiceManagerError,
    ServiceReloadNotifier,
    SystemdServiceManager,
)
from ski.state import StateDatabase


@dataclass
class FakeServiceManager:
    """Substituted boundary for the local systemd service manager."""

    active: bool = False
    calls: list[str] = field(default_factory=list)

    def is_active(self) -> bool:
        self.calls.append("is-active")
        return self.active

    def reload(self) -> None:
        self.calls.append("reload")


@dataclass
class FailingServiceManager:
    """A service-manager boundary which fails at one selected operation."""

    error_code: Literal["query_failed", "reload_failed"]

    def is_active(self) -> bool:
        raise ServiceManagerError(self.error_code)

    def reload(self) -> None:
        raise ServiceManagerError(self.error_code)


@dataclass
class ObservingServiceManager:
    """Read committed state when a substituted reload is requested."""

    database_path: Path
    calls: list[str] = field(default_factory=list)
    observed_values: list[str] = field(default_factory=list)

    def is_active(self) -> bool:
        self.calls.append("is-active")
        return True

    def reload(self) -> None:
        self.calls.append("reload")
        database = StateDatabase.open(self.database_path)
        try:
            with database.transaction() as connection:
                value = connection.execute(
                    "SELECT value FROM mutation ORDER BY rowid DESC LIMIT 1",
                ).fetchone()[0]
            self.observed_values.append(value)
        finally:
            database.close()


def test_inactive_service_is_a_success_without_reload() -> None:
    """A durable mutation succeeds even when the daemon is stopped."""
    manager = FakeServiceManager()

    result = ServiceReloadNotifier(manager).notify_after_mutation()

    assert result == NotificationResult(status="inactive")
    assert result.succeeded
    assert manager.calls == ["is-active"]


def test_active_service_is_reloaded_once() -> None:
    """An active service receives one reload request after durable work."""
    manager = FakeServiceManager(active=True)

    result = ServiceReloadNotifier(manager).notify_after_mutation()

    assert result == NotificationResult(status="reloaded")
    assert result.succeeded
    assert manager.calls == ["is-active", "reload"]


@pytest.mark.parametrize("error_code", ["query_failed", "reload_failed"])
def test_service_manager_failures_are_retryable_results(error_code: str) -> None:
    """Query and reload failures do not masquerade as durable mutation failure."""
    manager = FailingServiceManager(
        cast(Literal["query_failed", "reload_failed"], error_code),
    )

    result = ServiceReloadNotifier(manager).notify_after_mutation()

    assert result == NotificationResult(status="failed", error_code=error_code)
    assert not result.succeeded


def test_systemd_manager_uses_fixed_unit_and_recognizes_inactive_status() -> None:
    """The production adapter uses systemctl without a shell or output logging."""
    calls: list[tuple[str, ...]] = []

    def runner(command: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 3, stdout="inactive", stderr="")

    assert not SystemdServiceManager(runner).is_active()
    assert calls == [("systemctl", "is-active", "--quiet", "ski.service")]


def test_systemd_manager_maps_unexpected_status_to_query_failure() -> None:
    """Unknown systemctl state is not treated as an inactive service."""

    def runner(command: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 4, stdout="unknown", stderr="")

    with pytest.raises(ServiceManagerError) as error:
        SystemdServiceManager(runner).is_active()

    assert error.value.error_code == "query_failed"


def test_notification_is_after_commit_and_not_after_rollback(tmp_path: Path) -> None:
    """A caller can notify only after its transaction commits."""
    database_path = tmp_path / "state.sqlite3"
    database = StateDatabase.open(database_path, owner=True)
    try:
        with database.transaction() as connection:
            connection.execute("CREATE TABLE mutation (value TEXT NOT NULL)")
            connection.execute("INSERT INTO mutation VALUES ('committed')")

        manager = ObservingServiceManager(database_path)
        result = ServiceReloadNotifier(manager).notify_after_mutation()
        assert result.succeeded
        assert manager.calls == ["is-active", "reload"]
        assert manager.observed_values == ["committed"]

        with pytest.raises(RuntimeError):
            with database.transaction() as connection:
                connection.execute("INSERT INTO mutation VALUES ('rolled-back')")
                raise RuntimeError("rollback")

        assert manager.calls == ["is-active", "reload"]
        assert manager.observed_values == ["committed"]
    finally:
        database.close()
