"""Command-line interface for ski."""

from __future__ import annotations

import argparse

from ski.environment import load_environment


def build_parser() -> argparse.ArgumentParser:
    """Build the public command-line parser."""
    parser = argparse.ArgumentParser(
        prog="ski",
        description="Issue short-lived SSH certificates and load them into ssh-agent.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0",
    )
    return parser


def main() -> None:
    """Run the command-line entry point."""
    load_environment()
    build_parser().parse_args()
