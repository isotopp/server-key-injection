"""Documentation contracts for the offline production-host helper."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parents[1]
GUIDE = ROOT / "docs/TARGET-HOST.md"


def test_target_host_guide_covers_public_only_installation_and_contract() -> None:
    """The deployment guide keeps trust transfer and helper invocation explicit."""
    guide = GUIDE.read_text()
    for required in (
        "uv run ski ca show",
        "uv run ski ca public-key",
        "Never transfer the issuer's CA private key",
        "/opt/ski-authorize/config/user-ca.pub",
        "/opt/ski-authorize/config/authorization.toml",
        "/etc/ssh/sshd_config.d/60-ski-authorize.conf",
        "AuthorizedPrincipalsCommandUser ski-authz",
        "--ca-fingerprint %F %u %t %k",
        "TrustedUserCAKeys /opt/ski-authorize/config/user-ca.pub",
        "CASignatureAlgorithms ssh-ed25519",
        "AllowAgentForwarding no",
        "AllowTcpForwarding no",
        "X11Forwarding no",
        "OpenSSH 9 or later",
        "sudo sshd -t",
        "systemctl reload sshd",
        "systemctl reload ssh",
        "25-hour",
        "no route back to the office issuer",
    ):
        assert required in guide


def test_target_host_guide_links_from_operation_documentation() -> None:
    """Operators can find host deployment guidance from routine operations docs."""
    operation = (ROOT / "docs/OPERATION.md").read_text()
    assert "[`TARGET-HOST.md`](TARGET-HOST.md)" in operation
