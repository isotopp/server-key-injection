"""Command-line interface for ski."""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Sequence

from ski.runtime import ServiceRuntime


def _port(value: str) -> int:
    """Parse a public TCP port."""
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


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
    commands = parser.add_subparsers(dest="command")
    serve = commands.add_parser(
        "serve",
        help="run the foreground SSH issuer",
    )
    serve.add_argument("--bind", default="*", help="address to listen on")
    serve.add_argument(
        "--port",
        default=22,
        type=_port,
        help="TCP port to listen on",
    )
    return parser


async def serve_foreground(*, bind: str, port: int) -> None:
    """Run the configured foreground service."""
    runtime = ServiceRuntime(
        bind=bind,
        port=port,
    )
    remove_signal_handlers = runtime.install_signal_handlers()
    try:
        await runtime.start()
        while await runtime.wait_for_control_event() != "shutdown":
            await runtime.reload()
    finally:
        remove_signal_handlers()
        await runtime.close()


def main(argv: Sequence[str] | None = None) -> None:
    """Run the command-line entry point."""
    args = build_parser().parse_args(argv)
    if args.command == "serve":
        try:
            asyncio.run(serve_foreground(bind=args.bind, port=args.port))
        except KeyboardInterrupt:
            return
