"""Public command-line behaviour."""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from ski.cli import build_parser, main


def test_help_describes_certificate_issuance(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The CLI explains its user-facing certificate purpose."""
    with pytest.raises(SystemExit, match="0"):
        build_parser().parse_args(["--help"])

    assert "short-lived SSH certificates" in capsys.readouterr().out


def test_serve_accepts_tracer_listener_options() -> None:
    """The test issuer exposes the documented listener options."""
    args = build_parser().parse_args(["serve", "--bind", "127.0.0.1", "--port", "2222"])

    assert args.command == "serve"
    assert args.bind == "127.0.0.1"
    assert args.port == 2222


def test_serve_uses_production_defaults_and_rejects_invalid_ports() -> None:
    """The public service parser enforces the documented port range."""
    assert build_parser().parse_args(["serve"]).port == 22
    assert build_parser().parse_args(["serve"]).bind == "*"

    with pytest.raises(SystemExit, match="2"):
        build_parser().parse_args(["serve", "--port", "0"])


def test_version_does_not_require_service_configuration(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Global metadata commands remain usable without a database."""
    with pytest.raises(SystemExit, match="0"):
        main(["--version"])

    assert capsys.readouterr().out.startswith("ski ")


@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT])
def test_serve_exits_cleanly_on_service_signal(
    tmp_path: Path,
    signum: signal.Signals,
) -> None:
    """The foreground executable handles both service stop signals."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    environment = os.environ.copy()
    environment["SKI_CA_DATABASE"] = str(tmp_path / "state.sqlite3")
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from ski.cli import main; main()",
            "serve",
            "--bind",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 5
        output = ""
        while time.monotonic() < deadline and "service_ready" not in output:
            output += process.stderr.readline() if process.stderr is not None else ""
        assert "service_ready" in output

        process.send_signal(signum)
        assert process.wait(timeout=5) == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
