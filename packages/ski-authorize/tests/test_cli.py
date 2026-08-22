"""Public command-line behaviour for the host package."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from ski_authorize.cli import build_parser


def test_host_command_parser_exposes_version_metadata() -> None:
    """The independently installed helper has its own command identity."""
    parser = build_parser()

    assert parser.prog == "ski-authorize"
    assert parser.description is not None
    assert "local host" in parser.description


def test_host_command_parser_accepts_the_sshd_argument_shape() -> None:
    """The helper accepts the arguments supplied by OpenSSH."""
    args = build_parser().parse_args(
        [
            "--config",
            "/opt/ski-authorize/config/authorization.toml",
            "--ca-fingerprint",
            "SHA256:ca",
            "alice",
            "ssh-ed25519-cert-v01@openssh.com",
            "Y2VydGlmaWNhdGU=",
        ]
    )

    assert args.config == "/opt/ski-authorize/config/authorization.toml"
    assert args.ca_fingerprint == "SHA256:ca"
    assert args.target_user == "alice"
    assert args.certificate_type == "ssh-ed25519-cert-v01@openssh.com"
    assert args.certificate_base64 == "Y2VydGlmaWNhdGU="


def test_unimplemented_check_config_fails_without_principal_output() -> None:
    """The reserved configuration mode cannot authorize during scaffolding."""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from ski_authorize.cli import main; main()",
            "--check-config",
            "--config",
            "/tmp/authorization.toml",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert result.stdout == ""


def test_issuer_options_are_not_part_of_the_host_command() -> None:
    """Issuer state and network options are rejected by argparse."""
    with pytest.raises(SystemExit, match="2"):
        build_parser().parse_args(["--database", "issuer.sqlite3"])


@pytest.mark.skipif(os.geteuid() != 0, reason="production policy files are root-owned")
def test_check_config_reports_a_valid_root_owned_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The operator check command validates without producing a principal."""
    policy_path = tmp_path / "authorization.toml"
    policy_path.write_text(
        """
[ssh]
trusted_ca_fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
allowed_groups = []
allow_self_login_only = true
""".lstrip()
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["ski-authorize", "--check-config", "--config", str(policy_path)],
    )

    from ski_authorize.cli import main

    main()

    assert capsys.readouterr().out == "authorization policy is valid\n"
