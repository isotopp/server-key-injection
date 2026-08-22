"""Public command-line entry point for the host authorizer."""

from __future__ import annotations

import argparse

from . import __version__


def build_parser() -> argparse.ArgumentParser:
    """Build the initial host-package command parser."""
    parser = argparse.ArgumentParser(
        prog="ski-authorize",
        description="Authorize OpenSSH certificate principals on a local host.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main() -> None:
    """Run the host-package command."""
    build_parser().parse_args()
