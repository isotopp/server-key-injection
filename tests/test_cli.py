"""Public command-line behaviour."""

from __future__ import annotations

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
