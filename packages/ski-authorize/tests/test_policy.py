"""Public local-policy validation behaviour."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ski_authorize.policy import PolicyError, load_policy

VALID_FINGERPRINT = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def test_valid_policy_loads_from_a_protected_regular_file(tmp_path: Path) -> None:
    """A complete local policy becomes an immutable host-policy value."""
    policy_path = tmp_path / "authorization.toml"
    policy_path.write_text(
        """
[ssh]
trusted_ca_fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
allowed_groups = ["group:platform-ops", "group:database-oncall"]
allow_self_login_only = true
""".lstrip()
    )

    policy = load_policy(policy_path, expected_owner_uid=os.getuid())

    assert policy.trusted_ca_fingerprint.startswith("SHA256:")
    assert policy.allowed_groups == (
        "group:database-oncall",
        "group:platform-ops",
    )
    assert policy.allow_self_login_only is True


@pytest.mark.parametrize(
    "document",
    [
        """
[ssh]
allowed_groups = []
allow_self_login_only = true
""",
        """
[ssh]
trusted_ca_fingerprint = "bad"
allowed_groups = []
allow_self_login_only = true
""",
        f"""
[ssh]
trusted_ca_fingerprint = "{VALID_FINGERPRINT}"
allowed_groups = ["group:Platform"]
allow_self_login_only = true
""",
        f"""
[ssh]
trusted_ca_fingerprint = "{VALID_FINGERPRINT}"
allowed_groups = []
allow_self_login_only = false
""",
        f"""
[ssh]
trusted_ca_fingerprint = "{VALID_FINGERPRINT}"
allowed_groups = []
allow_self_login_only = true
extra = true
""",
        f"""
[ssh]
trusted_ca_fingerprint = "{VALID_FINGERPRINT}"
allowed_groups = []
allow_self_login_only = true
[ssh]
""",
    ],
)
def test_malformed_or_non_strict_policy_fails_closed(
    tmp_path: Path,
    document: str,
) -> None:
    """Missing, malformed, duplicate, and extra policy data is rejected."""
    policy_path = tmp_path / "authorization.toml"
    policy_path.write_text(document)

    with pytest.raises(PolicyError):
        load_policy(policy_path, expected_owner_uid=os.getuid())


def test_policy_file_must_be_regular_non_writable_and_root_owned(
    tmp_path: Path,
) -> None:
    """Symlinks, writable files, and the default non-root owner fail closed."""
    policy_path = tmp_path / "authorization.toml"
    policy_path.write_text(
        """
[ssh]
trusted_ca_fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
allowed_groups = []
allow_self_login_only = true
""".lstrip()
    )
    policy_path.chmod(0o664)
    with pytest.raises(PolicyError):
        load_policy(policy_path, expected_owner_uid=os.getuid())

    policy_path.chmod(0o640)
    link_path = tmp_path / "link.toml"
    link_path.symlink_to(policy_path)
    with pytest.raises(PolicyError):
        load_policy(link_path, expected_owner_uid=os.getuid())

    if os.getuid() != 0:
        with pytest.raises(PolicyError):
            load_policy(policy_path)
