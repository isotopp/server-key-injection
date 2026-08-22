"""Public command-line entry point for the host authorizer."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .authorization import AuthorizationDenied, authorize_certificate
from .certificate import CertificateError, parse_certificate
from .policy import PolicyError, load_policy


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


def main(argv: Sequence[str] | None = None) -> None:
    """Run the host-package command."""
    args = build_parser().parse_args(argv)
    if args.check_config:
        if (
            args.config is None
            or args.ca_fingerprint is not None
            or args.target_user is not None
            or args.certificate_type is not None
            or args.certificate_base64 is not None
        ):
            raise SystemExit("ski-authorize: --check-config requires only --config")
        try:
            load_policy(Path(args.config))
        except PolicyError as exc:
            raise SystemExit("ski-authorize: authorization policy is invalid") from exc
        print("authorization policy is valid")
        return

    positional = (
        args.target_user,
        args.certificate_type,
        args.certificate_base64,
    )
    if any(value is not None for value in positional) and not all(
        value is not None for value in positional
    ):
        raise SystemExit("ski-authorize: incomplete authorization arguments")
    if not all(value is not None for value in positional):
        raise SystemExit("ski-authorize: authorization arguments are required")
    if args.config is None or args.ca_fingerprint is None:
        raise SystemExit("ski-authorize: --config and --ca-fingerprint are required")

    try:
        policy = load_policy(Path(args.config))
        certificate = parse_certificate(args.certificate_type, args.certificate_base64)
        principal = authorize_certificate(
            policy,
            certificate,
            supplied_ca_fingerprint=args.ca_fingerprint,
            target_user=args.target_user,
        )
    except (AuthorizationDenied, CertificateError, PolicyError) as exc:
        raise SystemExit("ski-authorize: authorization denied") from exc
    print(principal)
