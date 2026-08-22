"""Public command-line behaviour for the host package."""

from __future__ import annotations

from ski_authorize.cli import build_parser


def test_host_command_parser_exposes_version_metadata() -> None:
    """The independently installed helper has its own command identity."""
    parser = build_parser()

    assert parser.prog == "ski-authorize"
    assert parser.description is not None
    assert "local host" in parser.description
