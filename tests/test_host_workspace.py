"""Black-box checks for the independently installable host package."""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_host_package_builds_and_exposes_its_own_version_command(
    tmp_path: Path,
) -> None:
    """A built host artifact runs without installing the issuer package."""
    output_dir = tmp_path / "dist"
    build = subprocess.run(
        [
            "uv",
            "build",
            "--package",
            "ski-authorize",
            "--out-dir",
            str(output_dir),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert build.returncode == 0, build.stderr
    wheels = sorted(output_dir.glob("ski_authorize-*.whl"))
    assert len(wheels) == 1

    command = subprocess.run(
        [
            "uv",
            "run",
            "--isolated",
            "--with",
            str(wheels[0]),
            "ski-authorize",
            "--version",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert command.returncode == 0, command.stderr
    assert command.stdout == "ski-authorize 0.1.0\n"
