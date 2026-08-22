"""Packaged host configuration samples."""

from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path

PACKAGE = Path(__file__).parents[1]


def test_built_host_artifact_contains_configuration_samples(tmp_path: Path) -> None:
    """The installable host artifact carries both reviewed sample files."""
    output_dir = tmp_path / "dist"
    build = subprocess.run(
        ["uv", "build", "--out-dir", str(output_dir)],
        cwd=PACKAGE,
        check=False,
        capture_output=True,
        text=True,
    )

    assert build.returncode == 0, build.stderr
    wheels = sorted(output_dir.glob("ski_authorize-*.whl"))
    assert len(wheels) == 1

    with zipfile.ZipFile(wheels[0]) as archive:
        names = set(archive.namelist())

    assert "ski_authorize/examples/authorization.toml" in names
    assert "ski_authorize/examples/60-ski-authorize.conf" in names


def test_samples_are_fail_closed_and_match_the_helper_contract() -> None:
    """Samples require deliberate CA/group edits and use the fixed SSH call."""
    policy = (PACKAGE / "src/ski_authorize/examples/authorization.toml").read_text()
    fragment = (
        PACKAGE / "src/ski_authorize/examples/60-ski-authorize.conf"
    ).read_text()

    assert 'trusted_ca_fingerprint = "REPLACE_WITH_SKI_CA_FINGERPRINT"' in policy
    assert "allowed_groups = []" in policy
    assert "allow_self_login_only = true" in policy
    assert (
        "--config /opt/ski-authorize/config/authorization.toml "
        "--ca-fingerprint %F %u %t %k"
    ) in fragment
    assert "AuthorizedPrincipalsCommandUser ski-authz" in fragment
    assert "# RevokedKeys /opt/ski-authorize/config/revoked.krl" in fragment

    for directive in (
        "PubkeyAuthentication yes",
        "PasswordAuthentication no",
        "KbdInteractiveAuthentication no",
        "TrustedUserCAKeys /opt/ski-authorize/config/user-ca.pub",
        "CASignatureAlgorithms ssh-ed25519",
        "AllowAgentForwarding no",
        "AllowTcpForwarding no",
        "X11Forwarding no",
    ):
        assert directive in fragment
