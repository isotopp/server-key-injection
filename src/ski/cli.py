"""Command-line interface for ski."""

from __future__ import annotations

import argparse
import asyncio
import base64
import getpass
import secrets
import sys
from collections.abc import Callable, Sequence
from typing import TextIO

import pyotp

from ski.configuration import load_runtime_configuration
from ski.identities import IdentityStoreError, SqliteIdentityStore
from ski.notify import ServiceReloadNotifier
from ski.runtime import ServiceRuntime
from ski.state import StateDatabase


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
    user = commands.add_parser("user", help="administer demo identities")
    user_commands = user.add_subparsers(dest="user_command", required=True)
    user_add = user_commands.add_parser("add", help="enroll a demo user")
    user_add.add_argument("username")
    user_commands.add_parser("list", help="list demo users")
    user_show = user_commands.add_parser("show", help="show one demo user")
    user_show.add_argument("username")
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


def _new_totp_secret() -> str:
    """Generate one 160-bit Base32 TOTP secret without padding."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _open_identity_store() -> tuple[StateDatabase, SqliteIdentityStore]:
    """Open the configured identity store for one short admin operation."""
    configuration = load_runtime_configuration(bind="127.0.0.1", port=22)
    database = StateDatabase.open(configuration.database)
    return database, SqliteIdentityStore(database)


def _run_user_add(
    username: str,
    *,
    secret_reader: Callable[[str], str],
    notifier: ServiceReloadNotifier,
    output: TextIO,
) -> None:
    database, store = _open_identity_store()
    try:
        password = secret_reader("Password: ")
        totp_secret = _new_totp_secret()
        user = store.create_user(username, password, totp_secret)
        notification = notifier.notify_after_mutation()
        uri = pyotp.TOTP(user.totp_secret).provisioning_uri(
            name=user.username,
            issuer_name="ski",
        )
        print(f"User created: {user.username}", file=output)
        print(f"TOTP secret: {user.totp_secret}", file=output)
        print(f"TOTP URI: {uri}", file=output)
        if not notification.succeeded:
            print(
                "User committed, but service notification failed; retry notification.",
                file=output,
            )
            raise SystemExit(
                "ski: service notification failed; mutation committed; "
                "retry notification",
            )
    except IdentityStoreError as exc:
        raise SystemExit(f"ski: user enrollment failed: {exc}") from exc
    finally:
        database.close()


def _run_user_show(username: str, *, output: TextIO) -> None:
    """Render one user's non-secret status and group snapshot."""
    database, store = _open_identity_store()
    try:
        user = store.get_user(username)
        status = "enabled" if user.enabled else "disabled"
        groups = ", ".join(user.groups) if user.groups else "(none)"
        print(f"User: {user.username}", file=output)
        print(f"Status: {status}", file=output)
        print(f"Groups: {groups}", file=output)
    except IdentityStoreError as exc:
        raise SystemExit(f"ski: unable to show user: {exc}") from exc
    finally:
        database.close()


def _run_user_list(*, output: TextIO) -> None:
    """Render all users with only canonical names and status."""
    database, store = _open_identity_store()
    try:
        for user in store.list_users():
            status = "enabled" if user.enabled else "disabled"
            print(f"{user.username} {status}", file=output)
    except IdentityStoreError as exc:
        raise SystemExit(f"ski: unable to list users: {exc}") from exc
    finally:
        database.close()


def main(
    argv: Sequence[str] | None = None,
    *,
    secret_reader=None,
    notifier: ServiceReloadNotifier | None = None,
    output: TextIO | None = None,
) -> None:
    """Run the command-line entry point."""
    args = build_parser().parse_args(argv)
    if args.command == "serve":
        try:
            asyncio.run(serve_foreground(bind=args.bind, port=args.port))
        except KeyboardInterrupt:
            return
    elif args.command == "user" and args.user_command == "add":
        _run_user_add(
            args.username,
            secret_reader=getpass.getpass if secret_reader is None else secret_reader,
            notifier=ServiceReloadNotifier() if notifier is None else notifier,
            output=output if output is not None else sys.stdout,
        )
    elif args.command == "user" and args.user_command == "show":
        _run_user_show(
            args.username, output=output if output is not None else sys.stdout
        )
    elif args.command == "user" and args.user_command == "list":
        _run_user_list(output=output if output is not None else sys.stdout)
