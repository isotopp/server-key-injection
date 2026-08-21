"""Static checks for the reviewed systemd deployment example."""

from __future__ import annotations

import getpass
import shutil
import subprocess
from pathlib import Path

import pytest

UNIT_PATH = Path(__file__).parents[1] / "docs" / "systemd" / "ski.service"
INSTALLATION_PATH = UNIT_PATH.with_name("INSTALLATION.md")


def test_systemd_unit_uses_application_owned_type_simple_service() -> None:
    """The example starts the app directly and delegates reload/stop by signal."""
    unit = UNIT_PATH.read_text()

    assert "Type=simple" in unit
    assert "ExecStart=/home/ski/.local/bin/ski serve" in unit
    assert "ExecReload=/bin/kill -HUP $MAINPID" in unit
    assert "KillSignal=SIGTERM" in unit
    assert "[Socket]" not in unit
    assert "sd_notify" not in unit


def test_systemd_unit_declares_hardening_and_operator_contract() -> None:
    """The template limits privileges while preserving configured state access."""
    unit = UNIT_PATH.read_text()

    assert "User=ski" in unit
    assert "Group=ski" in unit
    assert "WorkingDirectory=/home/ski/var/lib/ski" in unit
    assert "Environment=HOME=/home/ski" in unit
    assert "EnvironmentFile=-/home/ski/etc/env" in unit
    assert "StateDirectory=" not in unit
    assert "StateDirectoryMode=" not in unit
    assert "Restart=on-failure" in unit
    assert "TimeoutStartSec=30s" in unit
    assert "TimeoutStopSec=30s" in unit
    assert "AmbientCapabilities=CAP_NET_BIND_SERVICE" in unit
    assert "CapabilityBoundingSet=CAP_NET_BIND_SERVICE" in unit
    assert "NoNewPrivileges=true" in unit
    assert "ProtectSystem=strict" in unit
    assert "ProtectHome=read-only" in unit
    assert "ReadWritePaths=/home/ski/var/lib/ski" in unit
    assert "ReadOnlyPaths=/home/ski/etc" in unit


def test_installation_guide_covers_prebuilt_deployment_and_native_journal() -> None:
    """Operators get explicit installation, lifecycle, and readiness guidance."""
    guide = INSTALLATION_PATH.read_text()

    for expected in (
        "uv tool install . --with systemd-python",
        "systemctl daemon-reload",
        "systemctl enable --now ski.service",
        "systemctl reload ski.service",
        "systemctl stop ski.service",
        "journalctl -u ski.service SKI_EVENT=service_ready",
        "Type=simple",
        "SIGHUP",
        "SIGTERM",
        "active` state is not proof",
    ):
        assert expected in guide


@pytest.mark.skipif(
    shutil.which("systemd-analyze") is None,
    reason="systemd-analyze is not installed",
)
def test_systemd_analyze_accepts_substituted_example_on_linux(
    tmp_path: Path,
) -> None:
    """Linux deployments can syntax-check a path-substituted unit template."""
    unit = UNIT_PATH.read_text()
    unit = unit.replace("User=ski", f"User={getpass.getuser()}")
    unit = unit.replace("Group=ski", f"Group={getpass.getuser()}")
    unit = unit.replace(
        "WorkingDirectory=/home/ski/var/lib/ski",
        f"WorkingDirectory={tmp_path}",
    )
    unit = unit.replace("Environment=HOME=/home/ski", f"Environment=HOME={tmp_path}")
    unit = unit.replace(
        "ExecStart=/home/ski/.local/bin/ski serve", "ExecStart=/bin/true"
    )
    unit = unit.replace(
        "ReadWritePaths=/home/ski/var/lib/ski",
        f"ReadWritePaths={tmp_path}",
    )
    unit = unit.replace("ReadOnlyPaths=/home/ski/etc", "ReadOnlyPaths=/etc")
    candidate = tmp_path / "ski.service"
    candidate.write_text(unit)

    result = subprocess.run(
        ["systemd-analyze", "verify", str(candidate)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
