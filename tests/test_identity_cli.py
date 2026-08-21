"""Behavioural tests for demo identity administration commands."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from ski.cli import build_parser, main
from ski.identities import SqliteIdentityStore
from ski.notify import ServiceManagerError, ServiceReloadNotifier
from ski.state import StateDatabase


class _ActiveServiceManager:
    def is_active(self) -> bool:
        return True

    def reload(self) -> None:
        return None


def test_user_add_enrolls_a_user_and_displays_totp_material_once(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """User enrollment persists credentials and returns one TOTP enrollment result."""
    database_path = tmp_path / "state.sqlite3"
    monkeypatch.setenv("SKI_CA_DATABASE", str(database_path))
    output = io.StringIO()
    notifier = ServiceReloadNotifier(_ActiveServiceManager())

    main(
        ["user", "add", "alice"],
        secret_reader=lambda prompt: "correct horse battery staple",
        notifier=notifier,
        output=output,
    )

    rendered = output.getvalue()
    assert "alice" in rendered
    assert "otpauth://" in rendered
    assert "TOTP secret:" in rendered

    database = StateDatabase.open(database_path)
    try:
        store = SqliteIdentityStore(database)
        user = store.get_user("alice")
        assert user.enabled
        assert user.password_verifier.startswith("$argon2id$")
        assert user.totp_secret in rendered
    finally:
        database.close()


def test_user_add_has_no_secret_or_database_arguments_and_redacts_password(
    capsys: pytest.CaptureFixture[str],
    monkeypatch,
    tmp_path: Path,
) -> None:
    """CLI help has no secret/config overrides and output never echoes passwords."""
    with pytest.raises(SystemExit, match="0"):
        build_parser().parse_args(["user", "add", "--help"])
    help_text = capsys.readouterr().out
    for option in ("--password", "--totp-secret", "--database", "--config"):
        assert option not in help_text

    monkeypatch.setenv("SKI_CA_DATABASE", str(tmp_path / "state.sqlite3"))
    output = io.StringIO()
    password = "correct horse battery staple"
    main(
        ["user", "add", "alice"],
        secret_reader=lambda prompt: password,
        notifier=ServiceReloadNotifier(_ActiveServiceManager()),
        output=output,
    )
    rendered = output.getvalue()
    assert password not in rendered
    assert "$argon2id$" not in rendered


def test_user_show_and_list_are_redacted_read_only_views(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Read-only user commands expose status and groups but no credentials."""
    database_path = tmp_path / "state.sqlite3"
    monkeypatch.setenv("SKI_CA_DATABASE", str(database_path))
    database = StateDatabase.open(database_path)
    try:
        store = SqliteIdentityStore(database)
        user = store.create_user("alice", "secret-password", "JBSWY3DPEHPK3PXP")
        store.create_group("ops")
        store.add_membership("ops", user.username)
        secret = user.totp_secret
        verifier = user.password_verifier
    finally:
        database.close()

    show = io.StringIO()
    main(["user", "show", "alice"], output=show)
    show_text = show.getvalue()
    assert "alice" in show_text
    assert "enabled" in show_text
    assert "ops" in show_text
    assert secret not in show_text
    assert verifier not in show_text

    listing = io.StringIO()
    main(["user", "list"], output=listing)
    list_text = listing.getvalue()
    assert "alice" in list_text
    assert "enabled" in list_text
    assert "ops" not in list_text
    assert secret not in list_text
    assert verifier not in list_text


def test_user_add_commits_before_notification_and_succeeds_when_service_stopped(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Notification observes committed data, while an inactive service is benign."""
    database_path = tmp_path / "state.sqlite3"
    monkeypatch.setenv("SKI_CA_DATABASE", str(database_path))

    class CheckingServiceManager:
        def __init__(self, active: bool) -> None:
            self.active = active
            self.saw_committed_user = False

        def is_active(self) -> bool:
            return self.active

        def reload(self) -> None:
            database = StateDatabase.open(database_path)
            try:
                self.saw_committed_user = bool(
                    SqliteIdentityStore(database).list_users(),
                )
            finally:
                database.close()

    active_manager = CheckingServiceManager(active=True)
    main(
        ["user", "add", "alice"],
        secret_reader=lambda prompt: "password",
        notifier=ServiceReloadNotifier(active_manager),
        output=io.StringIO(),
    )
    assert active_manager.saw_committed_user

    stopped_manager = CheckingServiceManager(active=False)
    main(
        ["user", "add", "bob"],
        secret_reader=lambda prompt: "password",
        notifier=ServiceReloadNotifier(stopped_manager),
        output=io.StringIO(),
    )
    assert not stopped_manager.saw_committed_user


def test_user_add_reports_retryable_notification_failure_without_rollback(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """A reload failure is non-success but never rolls back or repeats enrollment."""
    database_path = tmp_path / "state.sqlite3"
    monkeypatch.setenv("SKI_CA_DATABASE", str(database_path))

    class FailingServiceManager:
        reload_calls = 0

        def is_active(self) -> bool:
            return True

        def reload(self) -> None:
            self.reload_calls += 1
            raise ServiceManagerError("reload_failed")

    manager = FailingServiceManager()
    with pytest.raises(SystemExit, match="notification failed"):
        main(
            ["user", "add", "alice"],
            secret_reader=lambda prompt: "password",
            notifier=ServiceReloadNotifier(manager),
            output=io.StringIO(),
        )
    assert manager.reload_calls == 1

    database = StateDatabase.open(database_path)
    try:
        assert tuple(
            user.username for user in SqliteIdentityStore(database).list_users()
        ) == ("alice",)
    finally:
        database.close()


def test_user_add_duplicate_is_atomic_and_does_not_notify(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """A rejected duplicate leaves one user and never reaches notification."""
    database_path = tmp_path / "state.sqlite3"
    monkeypatch.setenv("SKI_CA_DATABASE", str(database_path))

    class CountingServiceManager:
        reload_calls = 0

        def is_active(self) -> bool:
            return True

        def reload(self) -> None:
            self.reload_calls += 1

    manager = CountingServiceManager()
    notifier = ServiceReloadNotifier(manager)
    main(
        ["user", "add", "alice"],
        secret_reader=lambda prompt: "password",
        notifier=notifier,
        output=io.StringIO(),
    )
    with pytest.raises(SystemExit, match="enrollment failed"):
        main(
            ["user", "add", "alice"],
            secret_reader=lambda prompt: "different-password",
            notifier=notifier,
            output=io.StringIO(),
        )
    assert manager.reload_calls == 1

    database = StateDatabase.open(database_path)
    try:
        assert tuple(
            user.username for user in SqliteIdentityStore(database).list_users()
        ) == ("alice",)
    finally:
        database.close()
