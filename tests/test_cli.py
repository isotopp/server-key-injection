"""Public command-line behaviour."""

from __future__ import annotations

import pytest

from ski.cli import build_parser


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
