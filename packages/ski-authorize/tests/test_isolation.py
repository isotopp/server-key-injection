"""Black-box evidence for issuer/host package separation."""

from __future__ import annotations

import os
import shutil
import subprocess
import zipfile
from pathlib import Path

PACKAGE = Path(__file__).parents[1]


def _build_wheel(output_dir: Path) -> Path:
    build = subprocess.run(
        ["uv", "build", "--out-dir", str(output_dir)],
        cwd=PACKAGE,
        check=False,
        capture_output=True,
        text=True,
    )
    assert build.returncode == 0, build.stderr
    wheels = sorted(output_dir.glob("ski_authorize-*.whl"))
    assert len(wheels) == 1
    return wheels[0]


def test_host_wheel_has_no_issuer_package_or_runtime_dependencies(
    tmp_path: Path,
) -> None:
    """The host artifact contains only its own package and standard library use."""
    wheel = _build_wheel(tmp_path / "dist")

    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        metadata_name = next(
            name for name in names if name.endswith(".dist-info/METADATA")
        )
        metadata = archive.read(metadata_name).decode("utf-8")

    assert all(not name.startswith("ski/") for name in names)
    requirements = [
        line.removeprefix("Requires-Dist: ")
        for line in metadata.splitlines()
        if line.startswith("Requires-Dist:")
    ]
    assert requirements == ["asyncssh>=2.21.1"]


def test_host_version_command_has_no_stateful_side_effect(tmp_path: Path) -> None:
    """Version/help execution does not create issuer state or contact a service."""
    wheel = _build_wheel(tmp_path / "dist")
    environment = os.environ.copy()
    environment["HOME"] = str(tmp_path / "home")

    result = subprocess.run(
        [
            shutil.which("uv") or "uv",
            "run",
            "--isolated",
            "--with",
            str(wheel),
            "ski-authorize",
            "--version",
        ],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == "ski-authorize 0.1.0\n"
    assert not list(tmp_path.rglob("*.sqlite3"))


def test_host_source_has_no_issuer_or_remote_runtime_boundary() -> None:
    """The helper source contains no issuer endpoint, state, or listener path."""
    source = "\n".join(
        path.read_text()
        for path in sorted((PACKAGE / "src/ski_authorize").rglob("*.py"))
    )
    for forbidden in (
        "python-dotenv",
        "sqlite3",
        "SKI_CA_DATABASE",
        "ssh.example.com",
        "asyncssh.connect",
        "socket.socket",
        "uvicorn",
        "telemetry",
        "config-management",
    ):
        assert forbidden not in source
