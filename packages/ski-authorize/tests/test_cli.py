"""Public command-line behaviour for the host package."""

from __future__ import annotations

import base64
import os
import subprocess
import sys
import time
from pathlib import Path

import asyncssh
import pytest

from ski_authorize.cli import build_parser, main
from ski_authorize.policy import HostPolicy


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


def test_check_config_failure_has_no_principal_output() -> None:
    """A policy failure cannot accidentally authorize a principal."""
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


def test_valid_authorization_prints_one_group_principal(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The OpenSSH command contract emits exactly one permitted principal."""
    ca_key = asyncssh.generate_private_key("ssh-ed25519")
    user_key = asyncssh.generate_private_key("ssh-ed25519")
    now = int(time.time())
    certificate = ca_key.generate_user_certificate(
        user_key,
        "alice",
        principals=("alice", "group:platform-ops"),
        valid_after=now - 1,
        valid_before=now + 3600,
    )
    certificate_type, encoded = certificate.export_certificate().decode().split()
    fingerprint = ca_key.get_fingerprint()
    policy = HostPolicy(
        trusted_ca_fingerprint=fingerprint,
        allowed_groups=("group:platform-ops",),
        allow_self_login_only=True,
    )
    monkeypatch.setattr("ski_authorize.cli.load_policy", lambda path: policy)

    main(
        [
            "--config",
            "/opt/ski-authorize/config/authorization.toml",
            "--ca-fingerprint",
            fingerprint,
            "alice",
            certificate_type,
            base64.b64encode(base64.b64decode(encoded)).decode(),
        ]
    )

    captured = capsys.readouterr()
    assert captured.out == "group:platform-ops\n"
    assert captured.err == ""


def test_authorization_denial_has_no_principal_output(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A certificate binding failure produces only a safe stderr diagnostic."""
    ca_key = asyncssh.generate_private_key("ssh-ed25519")
    user_key = asyncssh.generate_private_key("ssh-ed25519")
    now = int(time.time())
    certificate = ca_key.generate_user_certificate(
        user_key,
        "alice",
        principals=("alice", "group:platform-ops"),
        valid_after=now - 1,
        valid_before=now + 3600,
    )
    certificate_type, encoded = certificate.export_certificate().decode().split()
    fingerprint = ca_key.get_fingerprint()
    policy = HostPolicy(
        trusted_ca_fingerprint=fingerprint,
        allowed_groups=("group:platform-ops",),
        allow_self_login_only=True,
    )
    monkeypatch.setattr("ski_authorize.cli.load_policy", lambda path: policy)

    with pytest.raises(SystemExit, match="authorization denied") as raised:
        main(
            [
                "--config",
                "/opt/ski-authorize/config/authorization.toml",
                "--ca-fingerprint",
                "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                "alice",
                certificate_type,
                encoded,
            ]
        )

    captured = capsys.readouterr()
    assert captured.out == ""
    assert str(raised.value) == "ski-authorize: authorization denied"
    assert captured.err == ""
    assert encoded not in captured.err


@pytest.mark.parametrize(
    "arguments",
    [
        ["--config", "/tmp/policy", "--ca-fingerprint", "SHA256:ca", "alice"],
        [
            "--config",
            "/tmp/policy",
            "--ca-fingerprint",
            "SHA256:ca",
            "alice",
            "certificate-body",
            "ssh-ed25519-cert-v01@openssh.com",
        ],
        ["--check-config", "--config", "/tmp/policy", "alice"],
    ],
)
def test_incomplete_reordered_or_mixed_arguments_fail_closed(
    arguments: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Only the packaged OpenSSH argument order can reach authorization."""
    with pytest.raises(SystemExit):
        main(arguments)
    assert capsys.readouterr().out == ""


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
