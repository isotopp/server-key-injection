"""Canonical identity, group, and SSH-principal policy."""

from __future__ import annotations

import re
from collections.abc import Sequence

USERNAME_PATTERN = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
GROUP_PATTERN = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")


class PolicyValidationError(ValueError):
    """Raised when a domain identity or principal violates canonical policy."""


def validate_username(username: object) -> str:
    """Return one canonical username or reject it."""
    if not isinstance(username, str) or USERNAME_PATTERN.fullmatch(username) is None:
        raise PolicyValidationError("username is not canonical")
    return username


def validate_group_name(name: object) -> str:
    """Return one canonical group name or reject it."""
    if not isinstance(name, str) or GROUP_PATTERN.fullmatch(name) is None:
        raise PolicyValidationError("group name is not canonical")
    return name


def build_principals(username: object, groups: Sequence[object]) -> tuple[str, ...]:
    """Build the canonical user and group principals for one identity."""
    canonical_username = validate_username(username)
    canonical_groups = tuple(validate_group_name(group) for group in groups)
    principals = (canonical_username, *(f"group:{group}" for group in canonical_groups))
    return validate_principals(principals)


def validate_principals(value: object) -> tuple[str, ...]:
    """Validate a canonical ordinary SSH-principal sequence."""
    if not isinstance(value, tuple) or not value:
        raise PolicyValidationError("certificate principals are malformed")
    if any(not isinstance(principal, str) for principal in value):
        raise PolicyValidationError("certificate principals are malformed")
    if len(set(value)) != len(value):
        raise PolicyValidationError("certificate principals contain duplicates")
    try:
        validate_username(value[0])
        for principal in value[1:]:
            if not isinstance(principal, str) or not principal.startswith("group:"):
                raise PolicyValidationError("certificate principals are malformed")
            validate_group_name(principal.removeprefix("group:"))
    except (TypeError, PolicyValidationError) as exc:
        if isinstance(exc, PolicyValidationError) and str(exc).startswith(
            "certificate principals",
        ):
            raise
        raise PolicyValidationError("certificate principals are malformed") from exc
    return value
