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
    parser.add_argument("--config")
    parser.add_argument("--ca-fingerprint")
    parser.add_argument("--check-config", action="store_true")
    parser.add_argument("target_user", nargs="?")
    parser.add_argument("certificate_type", nargs="?")
    parser.add_argument("certificate_base64", nargs="?")
    return parser


def main() -> None:
    """Run the host-package command."""
    args = build_parser().parse_args()
    if args.check_config:
        raise SystemExit("ski-authorize: configuration checking is not implemented")
    if any(
        value is not None
        for value in (
            args.config,
            args.ca_fingerprint,
            args.target_user,
            args.certificate_type,
            args.certificate_base64,
        )
    ):
        raise SystemExit("ski-authorize: authorization is not implemented")
