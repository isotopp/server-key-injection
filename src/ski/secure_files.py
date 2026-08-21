"""Bounded validation for issuer-managed files."""

from __future__ import annotations

import stat
from pathlib import Path


class SecureFileError(RuntimeError):
    """Raised when an issuer-managed file violates the local file policy."""


def validate_secure_file(
    path: Path,
    *,
    owner_uid: int,
    group_gid: int,
) -> Path:
    """Validate one existing issuer-managed file without following a symlink."""
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise SecureFileError("issuer-managed file is unavailable") from exc

    if not stat.S_ISREG(metadata.st_mode):
        raise SecureFileError("issuer-managed file is not regular")
    if metadata.st_uid != owner_uid or metadata.st_gid != group_gid:
        raise SecureFileError("issuer-managed file ownership is unsafe")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise SecureFileError("issuer-managed file permissions are unsafe")
    return path
