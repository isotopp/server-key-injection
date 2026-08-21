"""Post-mutation notification of the local systemd service."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol

SERVICE_UNIT = "ski.service"
CommandRunner = Callable[[tuple[str, ...]], subprocess.CompletedProcess[str]]


class ServiceManagerError(RuntimeError):
    """A local service-manager operation could not be completed."""

    def __init__(self, error_code: Literal["query_failed", "reload_failed"]) -> None:
        super().__init__(error_code)
        self.error_code = error_code


class ServiceManager(Protocol):
    """Minimal boundary needed to inspect and reload the local service."""

    def is_active(self) -> bool:
        """Return whether the fixed local service unit is active."""

    def reload(self) -> None:
        """Ask the fixed local service unit to reload."""


@dataclass(frozen=True)
class NotificationResult:
    """Outcome of the best-effort post-mutation service notification."""

    status: Literal["inactive", "reloaded", "failed"]
    error_code: str | None = None

    @property
    def succeeded(self) -> bool:
        """Return whether durable work can be considered successful."""
        return self.status != "failed"


def _run_systemctl(command: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    """Run one fixed-argument systemctl command without invoking a shell."""
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
    )


class SystemdServiceManager:
    """Address only the local ``ski.service`` unit through systemctl."""

    def __init__(self, runner: CommandRunner = _run_systemctl) -> None:
        self._runner = runner

    def is_active(self) -> bool:
        """Inspect service state without exposing command output."""
        try:
            result = self._runner(("systemctl", "is-active", "--quiet", SERVICE_UNIT))
        except OSError as exc:
            raise ServiceManagerError("query_failed") from exc
        if result.returncode == 0:
            return True
        if result.returncode == 3:
            return False
        raise ServiceManagerError("query_failed")

    def reload(self) -> None:
        """Request one reload and fail without retrying or rolling back work."""
        try:
            result = self._runner(("systemctl", "reload", SERVICE_UNIT))
        except OSError as exc:
            raise ServiceManagerError("reload_failed") from exc
        if result.returncode != 0:
            raise ServiceManagerError("reload_failed")


class ServiceReloadNotifier:
    """Notify an active local service after a durable mutation commits."""

    def __init__(self, manager: ServiceManager | None = None) -> None:
        self._manager = SystemdServiceManager() if manager is None else manager

    def notify_after_mutation(self) -> NotificationResult:
        """Reload an active service, preserving mutation success if it is stopped."""
        try:
            if not self._manager.is_active():
                return NotificationResult(status="inactive")
            self._manager.reload()
        except ServiceManagerError as exc:
            return NotificationResult(status="failed", error_code=exc.error_code)
        return NotificationResult(status="reloaded")
