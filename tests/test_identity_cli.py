"""Behavioural tests for demo identity administration commands."""

from __future__ import annotations

import io
from pathlib import Path

import pyotp
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


class _CountingServiceManager:
    def __init__(self) -> None:
        self.reload_calls = 0

    def is_active(self) -> bool:
        return True

    def reload(self) -> None:
        self.reload_calls += 1


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


@pytest.mark.parametrize(
    "command",
    [
        ["user", "add", "--help"],
        ["user", "show", "--help"],
        ["user", "list", "--help"],
        ["user", "enable", "--help"],
        ["user", "disable", "--help"],
        ["user", "password", "set", "--help"],
        ["user", "totp", "regenerate", "--help"],
        ["group", "add", "--help"],
        ["group", "remove", "--help"],
        ["group", "show", "--help"],
        ["group", "list", "--help"],
        ["group", "member", "add", "--help"],
        ["group", "member", "remove", "--help"],
    ],
)
def test_identity_command_help_never_opens_the_database(
    command: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Every identity command documents itself before any state access."""
    with pytest.raises(SystemExit, match="0"):
        build_parser().parse_args(command)
    assert "usage:" in capsys.readouterr().out


def test_group_add_show_and_list_expose_only_canonical_group_data(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Group commands create and inspect names without credential material."""
    database_path = tmp_path / "state.sqlite3"
    monkeypatch.setenv("SKI_CA_DATABASE", str(database_path))
    notifier = ServiceReloadNotifier(_ActiveServiceManager())

    added = io.StringIO()
    main(["group", "add", "platform-ops"], notifier=notifier, output=added)
    assert "platform-ops" in added.getvalue()

    shown = io.StringIO()
    main(["group", "show", "platform-ops"], output=shown)
    assert shown.getvalue().splitlines() == [
        "Group: platform-ops",
        "Members: (none)",
    ]

    listing = io.StringIO()
    main(["group", "list"], output=listing)
    assert listing.getvalue().splitlines() == ["platform-ops"]


def test_group_membership_add_remove_is_atomic_and_rejects_duplicates(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Membership commands update one edge and reject duplicate or absent edges."""
    database_path = tmp_path / "state.sqlite3"
    monkeypatch.setenv("SKI_CA_DATABASE", str(database_path))
    database = StateDatabase.open(database_path)
    try:
        store = SqliteIdentityStore(database)
        store.create_user("alice", "password", "JBSWY3DPEHPK3PXP")
        store.create_group("ops")
    finally:
        database.close()

    manager = _CountingServiceManager()
    notifier = ServiceReloadNotifier(manager)
    main(
        ["group", "member", "add", "ops", "alice"],
        notifier=notifier,
        output=io.StringIO(),
    )
    assert manager.reload_calls == 1
    with pytest.raises(SystemExit, match="membership"):
        main(
            ["group", "member", "add", "ops", "alice"],
            notifier=notifier,
            output=io.StringIO(),
        )
    assert manager.reload_calls == 1

    shown = io.StringIO()
    main(["group", "show", "ops"], output=shown)
    assert shown.getvalue().splitlines() == ["Group: ops", "Members: alice"]

    main(
        ["group", "member", "remove", "ops", "alice"],
        notifier=notifier,
        output=io.StringIO(),
    )
    assert manager.reload_calls == 2
    with pytest.raises(SystemExit, match="membership"):
        main(
            ["group", "member", "remove", "ops", "alice"],
            notifier=notifier,
            output=io.StringIO(),
        )
    assert manager.reload_calls == 2


def test_group_remove_requires_empty_group(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Group removal rejects memberships and deletes only empty groups."""
    database_path = tmp_path / "state.sqlite3"
    monkeypatch.setenv("SKI_CA_DATABASE", str(database_path))
    database = StateDatabase.open(database_path)
    try:
        store = SqliteIdentityStore(database)
        store.create_user("alice", "password", "JBSWY3DPEHPK3PXP")
        store.create_group("ops")
        store.create_group("empty")
        store.add_membership("ops", "alice")
    finally:
        database.close()

    manager = _CountingServiceManager()
    notifier = ServiceReloadNotifier(manager)
    with pytest.raises(SystemExit, match="group removal failed"):
        main(
            ["group", "remove", "ops"],
            notifier=notifier,
            output=io.StringIO(),
        )
    assert manager.reload_calls == 0

    main(
        ["group", "remove", "empty"],
        notifier=notifier,
        output=io.StringIO(),
    )
    assert manager.reload_calls == 1

    database = StateDatabase.open(database_path)
    try:
        assert SqliteIdentityStore(database).list_groups() == ("ops",)
    finally:
        database.close()


def test_user_enable_disable_preserves_credentials_and_groups(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Account status commands change only eligibility."""
    database_path = tmp_path / "state.sqlite3"
    monkeypatch.setenv("SKI_CA_DATABASE", str(database_path))
    database = StateDatabase.open(database_path)
    try:
        store = SqliteIdentityStore(database)
        store.create_user("alice", "password", "JBSWY3DPEHPK3PXP")
        store.create_group("ops")
        store.add_membership("ops", "alice")
        original = store.get_user("alice")
    finally:
        database.close()

    notifier = ServiceReloadNotifier(_ActiveServiceManager())
    main(["user", "disable", "alice"], notifier=notifier, output=io.StringIO())
    main(["user", "enable", "alice"], notifier=notifier, output=io.StringIO())

    database = StateDatabase.open(database_path)
    try:
        updated = SqliteIdentityStore(database).get_user("alice")
        assert updated.enabled
        assert updated.password_verifier == original.password_verifier
        assert updated.totp_secret == original.totp_secret
        assert updated.groups == original.groups == ("ops",)
    finally:
        database.close()


def test_user_password_set_replaces_verifier_without_exposing_secret(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Password replacement accepts only concealed input and rotates verification."""
    database_path = tmp_path / "state.sqlite3"
    monkeypatch.setenv("SKI_CA_DATABASE", str(database_path))
    database = StateDatabase.open(database_path)
    try:
        store = SqliteIdentityStore(database)
        original = store.create_user("alice", "old-password", "JBSWY3DPEHPK3PXP")
        old_verifier = original.password_verifier
    finally:
        database.close()

    new_password = "new-password"
    output = io.StringIO()
    main(
        ["user", "password", "set", "alice"],
        secret_reader=lambda prompt: new_password,
        notifier=ServiceReloadNotifier(_ActiveServiceManager()),
        output=output,
    )
    assert new_password not in output.getvalue()
    assert "$argon2id$" not in output.getvalue()

    database = StateDatabase.open(database_path)
    try:
        store = SqliteIdentityStore(database)
        updated = store.get_user("alice")
        assert updated.password_verifier != old_verifier
        assert not store.verify_password("alice", "old-password")
        assert store.verify_password("alice", new_password)
    finally:
        database.close()


def test_user_totp_regenerate_replaces_secret_and_displays_new_enrollment(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """TOTP regeneration atomically invalidates the prior secret."""
    database_path = tmp_path / "state.sqlite3"
    monkeypatch.setenv("SKI_CA_DATABASE", str(database_path))
    database = StateDatabase.open(database_path)
    try:
        store = SqliteIdentityStore(database)
        original = store.create_user("alice", "password", "JBSWY3DPEHPK3PXP")
        old_secret = original.totp_secret
        old_code = pyotp.TOTP(old_secret).now()
    finally:
        database.close()

    output = io.StringIO()
    main(
        ["user", "totp", "regenerate", "alice"],
        notifier=ServiceReloadNotifier(_ActiveServiceManager()),
        output=output,
    )
    rendered = output.getvalue()
    assert "TOTP secret:" in rendered
    assert "otpauth://" in rendered
    assert old_secret not in rendered

    database = StateDatabase.open(database_path)
    try:
        store = SqliteIdentityStore(database)
        updated = store.get_user("alice")
        assert updated.totp_secret != old_secret
        assert not store.verify_totp("alice", old_code)
        assert store.verify_totp("alice", pyotp.TOTP(updated.totp_secret).now())
    finally:
        database.close()
