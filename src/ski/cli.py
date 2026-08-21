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

from ski.ca import CAFileError
from ski.ca_commands import (
    initialize_ca,
    list_ca_events,
    read_ca_public_key,
    show_ca_records,
    verify_ca_state,
)
from ski.configuration import ConfigurationError, load_runtime_configuration
from ski.identities import (
    GroupAdministration,
    IdentityStoreError,
    SqliteIdentityStore,
    UserAdministration,
)
from ski.identity_commands import list_users as list_identity_users
from ski.identity_commands import show_user as show_identity_user
from ski.notify import ServiceReloadNotifier
from ski.runtime import ServiceRuntime
from ski.state import StateDatabase, StateError


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
    for status in ("enable", "disable"):
        status_parser = user_commands.add_parser(status, help=f"{status} a demo user")
        status_parser.add_argument("username")
    password = user_commands.add_parser("password", help="manage a user password")
    password_commands = password.add_subparsers(dest="password_command", required=True)
    password_set = password_commands.add_parser("set", help="replace a password")
    password_set.add_argument("username")
    totp = user_commands.add_parser("totp", help="manage a user TOTP secret")
    totp_commands = totp.add_subparsers(dest="totp_command", required=True)
    totp_regenerate = totp_commands.add_parser(
        "regenerate",
        help="replace a TOTP secret",
    )
    totp_regenerate.add_argument("username")
    group = commands.add_parser("group", help="administer demo groups")
    group_commands = group.add_subparsers(dest="group_command", required=True)
    group_add = group_commands.add_parser("add", help="create a demo group")
    group_add.add_argument("group")
    group_remove = group_commands.add_parser("remove", help="remove an empty group")
    group_remove.add_argument("group")
    group_show = group_commands.add_parser("show", help="show group members")
    group_show.add_argument("group")
    group_commands.add_parser("list", help="list demo groups")
    member = group_commands.add_parser("member", help="manage group membership")
    member_commands = member.add_subparsers(dest="member_command", required=True)
    for member_action in ("add", "remove"):
        member_parser = member_commands.add_parser(
            member_action,
            help=f"{member_action} group membership",
        )
        member_parser.add_argument("group")
        member_parser.add_argument("username")

    ca = commands.add_parser("ca", help="manage the persistent user CA")
    ca_commands = ca.add_subparsers(dest="ca_command", required=True)
    ca_commands.add_parser("init", help="initialize the Ed25519 user CA")
    ca_show = ca_commands.add_parser("show", help="show public CA status")
    ca_show.add_argument(
        "--all",
        action="store_true",
        help="show all known CA records",
    )
    ca_public_key = ca_commands.add_parser(
        "public-key",
        help="print a public CA key",
    )
    ca_public_key.add_argument(
        "--fingerprint",
        help="select a CA by fingerprint",
    )
    ca_log = ca_commands.add_parser("log", help="inspect CA events")
    log_commands = ca_log.add_subparsers(dest="log_command", required=True)
    log_list = log_commands.add_parser("list", help="list redacted CA events")
    log_list.add_argument("--serial")
    log_list.add_argument("--user")
    log_list.add_argument("--event")
    log_list.add_argument("--from", dest="from_time")
    log_list.add_argument("--to", dest="to_time")
    log_commands.add_parser("verify", help="verify CA state consistency")
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


def _run_ca_init(
    *,
    notifier: ServiceReloadNotifier,
    output: TextIO,
) -> None:
    """Initialize one configured Ed25519 CA and its empty KRL."""
    try:
        ca = initialize_ca()
        notification = notifier.notify_after_mutation()
        print("CA initialized.", file=output)
        print(f"Algorithm: {ca.algorithm}", file=output)
        print(f"Fingerprint: {ca.fingerprint}", file=output)
        if not notification.succeeded:
            print(
                "CA committed, but service notification failed; retry notification.",
                file=output,
            )
            raise SystemExit(
                "ski: CA initialized; service notification failed; retry notification",
            )
    except (CAFileError, ConfigurationError, StateError) as exc:
        raise SystemExit("ski: CA initialization failed") from exc


def _run_ca_show(*, show_all: bool, output: TextIO) -> None:
    """Display redacted public CA status without notifying the daemon."""
    try:
        records = show_ca_records(show_all=show_all)
        if not records:
            raise SystemExit("ski: no CA is initialized")
        for ca in records:
            print(f"CA ID: {ca.ca_id}", file=output)
            print(f"Algorithm: {ca.algorithm}", file=output)
            print(f"Fingerprint: {ca.fingerprint}", file=output)
            print(f"Status: {ca.status}", file=output)
            print(f"Activated: {ca.activated_at}", file=output)
    except (ConfigurationError, StateError) as exc:
        raise SystemExit("ski: unable to show CA") from exc


def _run_ca_public_key(*, fingerprint: str | None, output: TextIO) -> None:
    """Print one selected CA public key and no private metadata."""
    try:
        public_key = read_ca_public_key(fingerprint=fingerprint)
        if public_key is None:
            raise SystemExit("ski: requested CA is unavailable")
        print(public_key, file=output)
    except (ConfigurationError, StateError, UnicodeError) as exc:
        raise SystemExit("ski: unable to read CA public key") from exc


def _run_ca_log_list(
    *,
    serial: str | None,
    user: str | None,
    event: str | None,
    from_time: str | None,
    to_time: str | None,
    output: TextIO,
) -> None:
    """Render a bounded, strictly filtered, redacted CA event view."""
    try:
        events = list_ca_events(
            serial=serial,
            user=user,
            event=event,
            from_time=from_time,
            to_time=to_time,
        )
        for line in events:
            print(line, file=output)
    except (ConfigurationError, StateError, ValueError) as exc:
        raise SystemExit("ski: unable to list CA log") from exc


def _run_ca_log_verify(*, output: TextIO) -> None:
    """Verify CA state without mutating the database or notifying the daemon."""
    try:
        verify_ca_state()
        print("CA state verified.", file=output)
    except (ConfigurationError, StateError) as exc:
        raise SystemExit("ski: CA state verification failed") from exc


def _open_identity_store() -> tuple[StateDatabase, SqliteIdentityStore]:
    """Open the configured identity store for one short admin operation."""
    configuration = load_runtime_configuration(
        bind="127.0.0.1",
        port=22,
        require_ordinary_ca=False,
    )
    database = StateDatabase.open(configuration.database)
    return database, SqliteIdentityStore(database)


def _require_user_administration(store: object) -> UserAdministration:
    """Require the optional demo user mutation capability before any work."""
    if not isinstance(store, UserAdministration):
        raise IdentityStoreError("user administration is unavailable")
    return store


def _require_group_administration(store: object) -> GroupAdministration:
    """Require the optional demo group mutation capability before any work."""
    if not isinstance(store, GroupAdministration):
        raise IdentityStoreError("group administration is unavailable")
    return store


def _complete_mutation(
    notifier: ServiceReloadNotifier,
    *,
    output: TextIO,
    success_lines: Sequence[str],
    committed_message: str | None = None,
) -> None:
    """Render durable success and handle one post-commit notification result."""
    notification = notifier.notify_after_mutation()
    for line in success_lines:
        print(line, file=output)
    if not notification.succeeded:
        if committed_message is not None:
            print(committed_message, file=output)
        raise SystemExit(
            "ski: service notification failed; mutation committed; retry notification",
        )


def _run_user_add(
    username: str,
    *,
    secret_reader: Callable[[str], str],
    notifier: ServiceReloadNotifier,
    output: TextIO,
) -> None:
    database, store = _open_identity_store()
    try:
        administration = _require_user_administration(store)
        password = secret_reader("Password: ")
        totp_secret = _new_totp_secret()
        user = administration.create_user(username, password, totp_secret)
        uri = pyotp.TOTP(user.totp_secret).provisioning_uri(
            name=user.username,
            issuer_name="ski",
        )
        _complete_mutation(
            notifier,
            output=output,
            success_lines=(
                f"User created: {user.username}",
                f"TOTP secret: {user.totp_secret}",
                f"TOTP URI: {uri}",
            ),
            committed_message=(
                "User committed, but service notification failed; retry notification."
            ),
        )
    except IdentityStoreError as exc:
        raise SystemExit(f"ski: user enrollment failed: {exc}") from exc
    finally:
        database.close()


def _run_user_show(username: str, *, output: TextIO) -> None:
    """Render one user's non-secret status and group snapshot."""
    try:
        user = show_identity_user(username)
        status = "enabled" if user.enabled else "disabled"
        groups = ", ".join(user.groups) if user.groups else "(none)"
        print(f"User: {user.username}", file=output)
        print(f"Status: {status}", file=output)
        print(f"Groups: {groups}", file=output)
    except IdentityStoreError as exc:
        raise SystemExit(f"ski: unable to show user: {exc}") from exc


def _run_user_list(*, output: TextIO) -> None:
    """Render all users with only canonical names and status."""
    try:
        for user in list_identity_users():
            status = "enabled" if user.enabled else "disabled"
            print(f"{user.username} {status}", file=output)
    except IdentityStoreError as exc:
        raise SystemExit(f"ski: unable to list users: {exc}") from exc


def _run_user_status(
    username: str,
    *,
    enabled: bool,
    notifier: ServiceReloadNotifier,
    output: TextIO,
) -> None:
    """Change one user's enabled state and notify after commit."""
    database, store = _open_identity_store()
    try:
        administration = _require_user_administration(store)
        user = administration.set_user_enabled(username, enabled)
        status = "enabled" if user.enabled else "disabled"
        _complete_mutation(
            notifier,
            output=output,
            success_lines=(f"User {user.username} is {status}.",),
            committed_message=(
                "User committed, but service notification failed; retry notification."
            ),
        )
    except IdentityStoreError as exc:
        raise SystemExit(f"ski: user status change failed: {exc}") from exc
    finally:
        database.close()


def _run_user_password_set(
    username: str,
    *,
    secret_reader: Callable[[str], str],
    notifier: ServiceReloadNotifier,
    output: TextIO,
) -> None:
    """Replace one password through concealed input and notify after commit."""
    database, store = _open_identity_store()
    try:
        administration = _require_user_administration(store)
        password = secret_reader("New password: ")
        user = administration.replace_password(username, password)
        _complete_mutation(
            notifier,
            output=output,
            success_lines=(f"Password updated: {user.username}",),
            committed_message=(
                "Password committed, but service notification failed; "
                "retry notification."
            ),
        )
    except IdentityStoreError as exc:
        raise SystemExit(f"ski: password replacement failed: {exc}") from exc
    finally:
        database.close()


def _run_user_totp_regenerate(
    username: str,
    *,
    notifier: ServiceReloadNotifier,
    output: TextIO,
) -> None:
    """Replace one TOTP secret and display its enrollment material once."""
    database, store = _open_identity_store()
    try:
        administration = _require_user_administration(store)
        user = administration.replace_totp_secret(username, _new_totp_secret())
        uri = pyotp.TOTP(user.totp_secret).provisioning_uri(
            name=user.username,
            issuer_name="ski",
        )
        _complete_mutation(
            notifier,
            output=output,
            success_lines=(
                f"TOTP regenerated: {user.username}",
                f"TOTP secret: {user.totp_secret}",
                f"TOTP URI: {uri}",
            ),
            committed_message=(
                "TOTP committed, but service notification failed; retry notification."
            ),
        )
    except IdentityStoreError as exc:
        raise SystemExit(f"ski: TOTP replacement failed: {exc}") from exc
    finally:
        database.close()


def _run_group_add(
    name: str,
    *,
    notifier: ServiceReloadNotifier,
    output: TextIO,
) -> None:
    """Create one group and notify after the committed mutation."""
    database, store = _open_identity_store()
    try:
        administration = _require_group_administration(store)
        administration.create_group(name)
        _complete_mutation(
            notifier,
            output=output,
            success_lines=(f"Group created: {name}",),
        )
    except IdentityStoreError as exc:
        raise SystemExit(f"ski: group creation failed: {exc}") from exc
    finally:
        database.close()


def _run_group_show(name: str, *, output: TextIO) -> None:
    """Render one group and its non-secret member names."""
    database, store = _open_identity_store()
    try:
        members = store.get_group_members(name)
        print(f"Group: {name}", file=output)
        rendered_members = ", ".join(members) if members else "(none)"
        print(f"Members: {rendered_members}", file=output)
    except IdentityStoreError as exc:
        raise SystemExit(f"ski: unable to show group: {exc}") from exc
    finally:
        database.close()


def _run_group_list(*, output: TextIO) -> None:
    """Render all canonical group names without credentials."""
    database, store = _open_identity_store()
    try:
        for name in store.list_groups():
            print(name, file=output)
    except IdentityStoreError as exc:
        raise SystemExit(f"ski: unable to list groups: {exc}") from exc
    finally:
        database.close()


def _run_group_remove(
    name: str,
    *,
    notifier: ServiceReloadNotifier,
    output: TextIO,
) -> None:
    """Remove an empty group and notify after commit."""
    database, store = _open_identity_store()
    try:
        administration = _require_group_administration(store)
        administration.remove_group(name)
        _complete_mutation(
            notifier,
            output=output,
            success_lines=(f"Group removed: {name}",),
        )
    except IdentityStoreError as exc:
        raise SystemExit(f"ski: group removal failed: {exc}") from exc
    finally:
        database.close()


def _run_group_membership(
    group: str,
    username: str,
    *,
    add: bool,
    notifier: ServiceReloadNotifier,
    output: TextIO,
) -> None:
    """Change one membership edge and notify after commit."""
    database, store = _open_identity_store()
    try:
        administration = _require_group_administration(store)
        if add:
            administration.add_membership(group, username)
            action = "added"
        else:
            administration.remove_membership(group, username)
            action = "removed"
        _complete_mutation(
            notifier,
            output=output,
            success_lines=(f"Membership {action}: {group} {username}",),
        )
    except IdentityStoreError as exc:
        raise SystemExit(f"ski: membership change failed: {exc}") from exc
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
    elif args.command == "user" and args.user_command in {"enable", "disable"}:
        _run_user_status(
            args.username,
            enabled=args.user_command == "enable",
            notifier=ServiceReloadNotifier() if notifier is None else notifier,
            output=output if output is not None else sys.stdout,
        )
    elif (
        args.command == "user"
        and args.user_command == "password"
        and args.password_command == "set"
    ):
        _run_user_password_set(
            args.username,
            secret_reader=getpass.getpass if secret_reader is None else secret_reader,
            notifier=ServiceReloadNotifier() if notifier is None else notifier,
            output=output if output is not None else sys.stdout,
        )
    elif args.command == "group" and args.group_command == "add":
        _run_group_add(
            args.group,
            notifier=ServiceReloadNotifier() if notifier is None else notifier,
            output=output if output is not None else sys.stdout,
        )
    elif args.command == "group" and args.group_command == "show":
        _run_group_show(args.group, output=output if output is not None else sys.stdout)
    elif args.command == "group" and args.group_command == "list":
        _run_group_list(output=output if output is not None else sys.stdout)
    elif args.command == "group" and args.group_command == "remove":
        _run_group_remove(
            args.group,
            notifier=ServiceReloadNotifier() if notifier is None else notifier,
            output=output if output is not None else sys.stdout,
        )
    elif args.command == "group" and args.group_command == "member":
        _run_group_membership(
            args.group,
            args.username,
            add=args.member_command == "add",
            notifier=ServiceReloadNotifier() if notifier is None else notifier,
            output=output if output is not None else sys.stdout,
        )
    elif (
        args.command == "user"
        and args.user_command == "totp"
        and args.totp_command == "regenerate"
    ):
        _run_user_totp_regenerate(
            args.username,
            notifier=ServiceReloadNotifier() if notifier is None else notifier,
            output=output if output is not None else sys.stdout,
        )
    elif args.command == "ca" and args.ca_command == "init":
        _run_ca_init(
            notifier=ServiceReloadNotifier() if notifier is None else notifier,
            output=output if output is not None else sys.stdout,
        )
    elif args.command == "ca" and args.ca_command == "show":
        _run_ca_show(
            show_all=args.all,
            output=output if output is not None else sys.stdout,
        )
    elif args.command == "ca" and args.ca_command == "public-key":
        _run_ca_public_key(
            fingerprint=args.fingerprint,
            output=output if output is not None else sys.stdout,
        )
    elif (
        args.command == "ca" and args.ca_command == "log" and args.log_command == "list"
    ):
        _run_ca_log_list(
            serial=args.serial,
            user=args.user,
            event=args.event,
            from_time=args.from_time,
            to_time=args.to_time,
            output=output if output is not None else sys.stdout,
        )
    elif (
        args.command == "ca"
        and args.ca_command == "log"
        and args.log_command == "verify"
    ):
        _run_ca_log_verify(output=output if output is not None else sys.stdout)
    elif args.command == "ca":
        raise SystemExit("ski: this CA command is not implemented yet")
