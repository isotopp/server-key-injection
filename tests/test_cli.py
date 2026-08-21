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
from support import runtime_environment


def test_help_describes_certificate_issuance(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The CLI explains its user-facing certificate purpose."""
    with pytest.raises(SystemExit, match="0"):
        build_parser().parse_args(["--help"])

    assert "short-lived SSH certificates" in capsys.readouterr().out


def test_cli_help_lists_the_current_service_and_identity_surface() -> None:
    """The public help exposes service, identity, and CA commands."""
    help_text = build_parser().format_help()
    for command in ("serve", "user", "group", "ca"):
        assert command in help_text
    command_line = next(
        line for line in help_text.splitlines() if line.startswith("  {")
    )
    assert command_line == "  {serve,user,group,ca}"


def test_serve_accepts_issuer_listener_options() -> None:
    """The issuer exposes the documented listener options."""
    args = build_parser().parse_args(["serve", "--bind", "127.0.0.1", "--port", "2222"])

    assert args.command == "serve"
    assert args.bind == "127.0.0.1"
    assert args.port == 2222


def test_ca_parser_exposes_only_the_epic_four_public_commands() -> None:
    """CA commands have public inspection and initialization surfaces only."""
    parser = build_parser()

    init = parser.parse_args(["ca", "init"])
    assert (init.command, init.ca_command) == ("ca", "init")

    show = parser.parse_args(["ca", "show", "--all"])
    assert show.all

    public_key = parser.parse_args(
        ["ca", "public-key", "--fingerprint", "SHA256:ca"],
    )
    assert public_key.fingerprint == "SHA256:ca"

    log_list = parser.parse_args(
        ["ca", "log", "list", "--serial", "7", "--event", "certificate_issued"],
    )
    assert (log_list.ca_command, log_list.log_command) == ("log", "list")
    assert (log_list.serial, log_list.event) == ("7", "certificate_issued")

    verify = parser.parse_args(["ca", "log", "verify"])
    assert (verify.ca_command, verify.log_command) == ("log", "verify")

    help_text = parser.format_help()
    assert "ca" in help_text
    for forbidden in ("rotate", "revoke", "reconcile", "--key-type", "--database"):
        assert forbidden not in help_text


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
    environment.update(runtime_environment(tmp_path, tmp_path / "state.sqlite3"))
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


def test_serve_reloads_on_sighup_without_exiting(tmp_path: Path) -> None:
    """SIGHUP reloads configuration and leaves the foreground service alive."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    environment = os.environ.copy()
    environment.update(runtime_environment(tmp_path, tmp_path / "state.sqlite3"))
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
        assert process.stderr is not None
        output = process.stderr.readline()
        assert "service_starting" in output
        output += process.stderr.readline()
        assert "service_ready" in output
        process.send_signal(signal.SIGHUP)
        reload_output = process.stderr.readline() + process.stderr.readline()
        assert "service_reload_accepted" in reload_output
        assert process.poll() is None
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=5) == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
