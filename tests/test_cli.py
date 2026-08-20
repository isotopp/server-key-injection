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
