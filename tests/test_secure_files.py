"""Behavioural tests for issuer-managed file policy."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ski.secure_files import SecureFileError, validate_secure_file


def test_accepts_owned_regular_file_without_group_or_world_write(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    path.write_bytes(b"state")
    path.chmod(0o600)

    assert (
        validate_secure_file(
            path,
            owner_uid=os.getuid(),
            group_gid=os.getgid(),
        )
        == path
    )


def test_rejects_symlink_even_when_target_is_safe(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"state")
    target.chmod(0o600)
    link = tmp_path / "state.sqlite3"
    link.symlink_to(target)

    with pytest.raises(SecureFileError, match="not regular"):
        validate_secure_file(
            link,
            owner_uid=os.getuid(),
            group_gid=os.getgid(),
        )


def test_rejects_non_regular_file(tmp_path: Path) -> None:
    with pytest.raises(SecureFileError, match="not regular"):
        validate_secure_file(
            tmp_path,
            owner_uid=os.getuid(),
            group_gid=os.getgid(),
        )


def test_rejects_wrong_owner_or_group_expectation(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    path.write_bytes(b"state")
    path.chmod(0o600)

    with pytest.raises(SecureFileError, match="ownership"):
        validate_secure_file(
            path,
            owner_uid=os.getuid() + 1,
            group_gid=os.getgid(),
        )


def test_rejects_group_writable_file(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    path.write_bytes(b"state")
    path.chmod(0o620)

    with pytest.raises(SecureFileError, match="permissions"):
        validate_secure_file(
            path,
            owner_uid=os.getuid(),
            group_gid=os.getgid(),
        )


def test_rejects_world_writable_file(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    path.write_bytes(b"state")
    path.chmod(0o602)

    with pytest.raises(SecureFileError, match="permissions"):
        validate_secure_file(
            path,
            owner_uid=os.getuid(),
            group_gid=os.getgid(),
        )
