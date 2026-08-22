"""Behavioural tests for persistent CA initialization commands."""

from __future__ import annotations

import io
import os
import sqlite3
import stat
import subprocess
from pathlib import Path

import asyncssh
import pytest

from ski.ca import CAFileError, CAFileWriter, load_validated_active_ca
from ski.cli import main
from ski.notify import ServiceManagerError, ServiceReloadNotifier
from ski.state import StateDatabase, StateError


class _StoppedServiceManager:
    def is_active(self) -> bool:
        return False

    def reload(self) -> None:
        raise AssertionError("a stopped service must not be reloaded")


class _FailingServiceManager:
    def is_active(self) -> bool:
        return True

    def reload(self) -> None:
        raise ServiceManagerError("reload_failed")


def _ca_environment(tmp_path: Path) -> dict[str, str]:
    return {
        "SKI_CA_DATABASE": str(tmp_path / "state.sqlite3"),
        "SKI_CA_PRIVATE_KEY": str(tmp_path / "user_ca"),
        "SKI_CA_PUBLIC_KEY": str(tmp_path / "user_ca.pub"),
        "SKI_CA_KRL": str(tmp_path / "revoked.krl"),
        "ORDINARY_CERT_EXTENSIONS": "pty",
    }


def test_ca_init_creates_protected_ed25519_material_and_public_status(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Initialization writes matching public material and an empty valid KRL."""
    for key, value in _ca_environment(tmp_path).items():
        monkeypatch.setenv(key, value)
    output = io.StringIO()

    main(
        ["ca", "init"],
        notifier=ServiceReloadNotifier(_StoppedServiceManager()),
        output=output,
    )

    private_path = tmp_path / "user_ca"
    public_path = tmp_path / "user_ca.pub"
    krl_path = tmp_path / "revoked.krl"
    assert stat.S_IMODE(private_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(public_path.stat().st_mode) == 0o644
    private_key = asyncssh.import_private_key(private_path.read_bytes())
    public_key = asyncssh.import_public_key(public_path.read_bytes())
    assert private_key.get_algorithm() == "ssh-ed25519"
    assert private_key.export_public_key() == public_key.export_public_key()
    assert (
        subprocess.run(
            ["ssh-keygen", "-Q", "-f", str(krl_path)],
            check=False,
            capture_output=True,
        ).returncode
        == 0
    )

    database = StateDatabase.open(tmp_path / "state.sqlite3", owner=True)
    try:
        ca = database.get_active_ca()
        assert ca is not None
        assert ca.fingerprint == private_key.get_fingerprint()
        assert ca.private_key_path == private_path
        assert len(database.list_events()) == 1
    finally:
        database.close()

    rendered = output.getvalue()
    assert "CA initialized" in rendered
    assert private_path.read_text(errors="ignore") not in rendered
    assert "BEGIN OPENSSH PRIVATE KEY" not in rendered
    assert "ssh-ed25519" in rendered


def test_active_ca_loader_rejects_symlinked_private_key(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Loading an active CA never follows a symlinked private key path."""
    for key, value in _ca_environment(tmp_path).items():
        monkeypatch.setenv(key, value)
    main(
        ["ca", "init"],
        notifier=ServiceReloadNotifier(_StoppedServiceManager()),
        output=io.StringIO(),
    )
    private_path = tmp_path / "user_ca"
    real_private_path = tmp_path / "real-user-ca"
    private_path.rename(real_private_path)
    private_path.symlink_to(real_private_path)

    database = StateDatabase.open(tmp_path / "state.sqlite3", owner=True)
    try:
        with pytest.raises(StateError, match="CA material"):
            load_validated_active_ca(
                database,
                private_path=private_path,
                public_path=tmp_path / "user_ca.pub",
            )
    finally:
        database.close()


def test_active_ca_loader_rejects_group_writable_public_key(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Loading an active CA rejects group-writable public material."""
    for key, value in _ca_environment(tmp_path).items():
        monkeypatch.setenv(key, value)
    main(
        ["ca", "init"],
        notifier=ServiceReloadNotifier(_StoppedServiceManager()),
        output=io.StringIO(),
    )
    (tmp_path / "user_ca.pub").chmod(0o664)

    database = StateDatabase.open(tmp_path / "state.sqlite3", owner=True)
    try:
        with pytest.raises(StateError, match="CA material"):
            load_validated_active_ca(
                database,
                private_path=tmp_path / "user_ca",
                public_path=tmp_path / "user_ca.pub",
            )
    finally:
        database.close()


def test_ca_file_writer_rejects_preexisting_symlink_target(tmp_path: Path) -> None:
    """CA initialization refuses a dangling symlink target."""
    private_path = tmp_path / "user_ca"
    private_path.symlink_to(tmp_path / "not-created")

    with pytest.raises(CAFileError, match="already exists"):
        CAFileWriter().install(
            private_path=private_path,
            public_path=tmp_path / "user_ca.pub",
            krl_path=tmp_path / "revoked.krl",
        )


def test_ca_file_writer_cleans_unsafe_installed_target(tmp_path: Path) -> None:
    """CA initialization compensates when an installed file is unsafe."""

    def unsafe_rename(
        source: str | os.PathLike[str],
        target: str | os.PathLike[str],
    ) -> None:
        os.replace(source, target)
        if Path(target).name == "user_ca":
            Path(target).chmod(0o620)

    with pytest.raises(CAFileError, match="unsafe"):
        CAFileWriter(rename=unsafe_rename).install(
            private_path=tmp_path / "user_ca",
            public_path=tmp_path / "user_ca.pub",
            krl_path=tmp_path / "revoked.krl",
        )

    assert not (tmp_path / "user_ca").exists()
    assert not (tmp_path / "user_ca.pub").exists()
    assert not (tmp_path / "revoked.krl").exists()


def test_ca_init_refuses_existing_material_without_mutation(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """A second initialization cannot overwrite files or create another CA."""
    environment = _ca_environment(tmp_path)
    for key, value in environment.items():
        monkeypatch.setenv(key, value)
    private_path = tmp_path / "user_ca"
    private_path.write_bytes(b"pre-existing-private-material")
    output = io.StringIO()

    with pytest.raises(
        SystemExit,
        match="CA initialization failed: CA output already exists",
    ):
        main(
            ["ca", "init"],
            notifier=ServiceReloadNotifier(_StoppedServiceManager()),
            output=output,
        )

    assert private_path.read_bytes() == b"pre-existing-private-material"
    database = StateDatabase.open(tmp_path / "state.sqlite3", owner=True)
    try:
        assert database.get_active_ca() is None
    finally:
        database.close()


@pytest.mark.parametrize(
    ("command", "summary"),
    (
        (("ca", "show"), "unable to show CA"),
        (("ca", "public-key"), "unable to read CA public key"),
        (("ca", "log", "list"), "unable to list CA log"),
        (("ca", "log", "verify"), "CA state verification failed"),
    ),
)
def test_ca_read_commands_include_safe_configuration_failure_reason(
    monkeypatch,
    tmp_path: Path,
    command: tuple[str, ...],
    summary: str,
) -> None:
    """CA read/verify errors identify a safe, actionable configuration cause."""
    environment = _ca_environment(tmp_path)
    environment["SKI_CA_DATABASE"] = str(tmp_path / "missing" / "state.sqlite3")
    for key, value in environment.items():
        monkeypatch.setenv(key, value)

    with pytest.raises(
        SystemExit,
        match=f"{summary}: SKI_CA_DATABASE parent directory is unavailable",
    ):
        main(command, output=io.StringIO())


def test_ca_show_and_public_key_are_redacted_read_only_views(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """CA inspection commands expose public material without daemon mutation."""
    for key, value in _ca_environment(tmp_path).items():
        monkeypatch.setenv(key, value)
    main(
        ["ca", "init"],
        notifier=ServiceReloadNotifier(_StoppedServiceManager()),
        output=io.StringIO(),
    )
    shown = io.StringIO()
    main(["ca", "show"], output=shown)
    rendered = shown.getvalue()
    assert "Algorithm: ssh-ed25519" in rendered
    assert "Status: active" in rendered
    assert str(tmp_path / "user_ca") not in rendered
    assert "BEGIN OPENSSH PRIVATE KEY" not in rendered

    public_key = io.StringIO()
    main(["ca", "public-key"], output=public_key)
    assert public_key.getvalue().startswith("ssh-ed25519 ")
    assert "BEGIN" not in public_key.getvalue()


def test_ca_init_notification_failure_preserves_durable_success(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """A post-commit reload failure is retryable and never rolls back the CA."""
    for key, value in _ca_environment(tmp_path).items():
        monkeypatch.setenv(key, value)
    with pytest.raises(SystemExit, match="notification failed"):
        main(
            ["ca", "init"],
            notifier=ServiceReloadNotifier(_FailingServiceManager()),
            output=io.StringIO(),
        )
    assert (tmp_path / "user_ca").exists()
    database = StateDatabase.open(tmp_path / "state.sqlite3", owner=True)
    try:
        assert database.get_active_ca() is not None
    finally:
        database.close()


def test_ca_log_list_filters_redacted_events_and_verify_checks_consistency(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """CA logs are bounded public views and verification is read-only."""
    for key, value in _ca_environment(tmp_path).items():
        monkeypatch.setenv(key, value)
    main(
        ["ca", "init"],
        notifier=ServiceReloadNotifier(_StoppedServiceManager()),
        output=io.StringIO(),
    )
    database = StateDatabase.open(tmp_path / "state.sqlite3", owner=True)
    try:
        ca = database.get_active_ca()
        assert ca is not None
        database.record_certificate_with_event(
            ca_id=ca.ca_id,
            serial=7,
            identity="alice",
            public_key_fingerprint="SHA256:user-key",
            principals=("alice", "group:platform-ops"),
            valid_after=1_700_000_000,
            valid_before=1_700_000_000 + 25 * 60 * 60,
            request_id="request-ordinary-1",
        )
    finally:
        database.close()

    listed = io.StringIO()
    main(
        ["ca", "log", "list", "--user", "alice", "--serial", "7"],
        output=listed,
    )
    rendered = listed.getvalue()
    assert "certificate_issued" in rendered
    assert "alice" in rendered
    assert "serial=7" in rendered
    assert "SHA256:user-key" not in rendered
    assert "BEGIN" not in rendered

    verified = io.StringIO()
    main(["ca", "log", "verify"], output=verified)
    assert verified.getvalue() == "CA state verified.\n"

    connection = sqlite3.connect(tmp_path / "state.sqlite3")
    connection.execute(
        "UPDATE certificates SET request_id = 'tampered' WHERE serial = '7'",
    )
    connection.commit()
    connection.close()
    with pytest.raises(SystemExit, match="verification failed"):
        main(["ca", "log", "verify"], output=io.StringIO())


def test_ca_file_writer_cleans_all_targets_when_rename_fails(tmp_path: Path) -> None:
    """Atomic CA installation removes newly installed files on a boundary error."""
    calls = 0

    def failing_rename(
        source: str | os.PathLike[str], target: str | os.PathLike[str]
    ) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("rename boundary")
        os.replace(source, target)

    writer = CAFileWriter(rename=failing_rename)
    with pytest.raises(CAFileError):
        writer.install(
            private_path=tmp_path / "user_ca",
            public_path=tmp_path / "user_ca.pub",
            krl_path=tmp_path / "revoked.krl",
        )

    assert not (tmp_path / "user_ca").exists()
    assert not (tmp_path / "user_ca.pub").exists()
    assert not (tmp_path / "revoked.krl").exists()
    assert not list(tmp_path.glob(".*"))
