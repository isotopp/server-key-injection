"""Strict, local host authorization policy loading."""

from __future__ import annotations

import os
import re
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class PolicyError(ValueError):
    """Raised when local authorization policy cannot be trusted."""


_FINGERPRINT_PATTERN = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
_GROUP_PATTERN = re.compile(r"group:[a-z][a-z0-9-]{0,62}\Z")
_POLICY_KEYS = frozenset(
    {"trusted_ca_fingerprint", "allowed_groups", "allow_self_login_only"}
)


@dataclass(frozen=True, slots=True)
class HostPolicy:
    """Immutable policy used for one host-local authorization decision."""

    trusted_ca_fingerprint: str
    allowed_groups: tuple[str, ...]
    allow_self_login_only: bool


def _read_protected_text(path: Path, *, expected_owner_uid: int) -> str:
    """Read one regular, non-writable file without following its final link."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PolicyError("authorization policy is unavailable") from exc

    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise PolicyError("authorization policy is not a regular file")
        if metadata.st_uid != expected_owner_uid:
            raise PolicyError("authorization policy ownership is unsafe")
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise PolicyError("authorization policy permissions are unsafe")
        with os.fdopen(descriptor, encoding="utf-8") as stream:
            descriptor = -1
            return stream.read()
    except PolicyError:
        raise
    except (OSError, UnicodeError) as exc:
        raise PolicyError("authorization policy is unreadable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _parse_policy(document: str) -> HostPolicy:
    """Parse and strictly validate one TOML policy document."""
    try:
        raw: Any = tomllib.loads(document)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError("authorization policy is malformed") from exc

    if not isinstance(raw, dict) or set(raw) != {"ssh"}:
        raise PolicyError("authorization policy schema is unsupported")
    section = raw["ssh"]
    if not isinstance(section, dict) or set(section) != _POLICY_KEYS:
        raise PolicyError("authorization policy schema is unsupported")

    fingerprint = section["trusted_ca_fingerprint"]
    if not isinstance(fingerprint, str) or not _FINGERPRINT_PATTERN.fullmatch(
        fingerprint,
    ):
        raise PolicyError("authorization CA fingerprint is malformed")

    allowed_groups = section["allowed_groups"]
    if not isinstance(allowed_groups, list):
        raise PolicyError("authorization groups are malformed")
    if any(
        not isinstance(group, str) or _GROUP_PATTERN.fullmatch(group) is None
        for group in allowed_groups
    ):
        raise PolicyError("authorization groups are malformed")
    if len(set(allowed_groups)) != len(allowed_groups):
        raise PolicyError("authorization groups contain duplicates")

    allow_self_login_only = section["allow_self_login_only"]
    if allow_self_login_only is not True:
        raise PolicyError("self-login policy must be enabled")

    return HostPolicy(
        trusted_ca_fingerprint=fingerprint,
        allowed_groups=tuple(sorted(allowed_groups)),
        allow_self_login_only=True,
    )


def load_policy(path: Path, *, expected_owner_uid: int = 0) -> HostPolicy:
    """Load a protected local policy through the public host-policy boundary."""
    return _parse_policy(
        _read_protected_text(path, expected_owner_uid=expected_owner_uid)
    )
