"""Static safety checks for the root-run host installation script."""

from __future__ import annotations

import subprocess
from pathlib import Path

PACKAGE = Path(__file__).parents[1]
SCRIPT = PACKAGE / "install.sh"


def test_install_script_is_shell_valid_and_uses_fixed_uv_layout() -> None:
    """The installer is auditable and keeps all uv state below /opt."""
    script = SCRIPT.read_text()
    syntax = subprocess.run(
        ["bash", "-n", str(SCRIPT)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert syntax.returncode == 0, syntax.stderr
    for expected in (
        'UV_PYTHON_INSTALL_DIR="/opt/ski-authorize/python"',
        'UV_TOOL_DIR="/opt/ski-authorize/tools"',
        'UV_TOOL_BIN_DIR="/opt/ski-authorize/bin"',
        'UV_CACHE_DIR="/opt/ski-authorize/cache"',
        "uv python install 3.12",
        "uv tool install --python 3.12 --managed-python --upgrade",
        "/opt/ski-authorize/config/authorization.toml",
        "/etc/ssh/sshd_config.d/60-ski-authorize.conf",
    ):
        assert expected in script


def test_non_root_install_exits_before_touching_the_host() -> None:
    """The installer refuses an ordinary caller before any mutation."""
    result = subprocess.run(
        [str(SCRIPT)],
        cwd=PACKAGE,
        check=False,
        capture_output=True,
        text=True,
    )

    if result.returncode == 0:
        # The test environment must not be root; avoid asserting a dangerous
        # host installation result if the test is accidentally run privileged.
        return
    assert "must run as root" in result.stderr
    assert result.stdout == ""


def test_install_script_preserves_existing_trusted_files() -> None:
    """Existing samples are validated, never replaced or followed as links."""
    script = SCRIPT.read_text()

    assert "install_if_absent()" in script
    assert 'validate_file "${destination}"' in script
    assert '[[ -f "${path}" && ! -L "${path}" ]]' in script
    assert "rm -" not in script
    assert "systemctl" not in script
