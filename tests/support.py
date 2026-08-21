"""Shared test configuration helpers."""

from __future__ import annotations

from pathlib import Path


def runtime_environment(tmp_path: Path, database: Path) -> dict[str, str]:
    """Return a complete pre-Epic-4 runtime configuration snapshot."""
    return {
        "SKI_CA_DATABASE": str(database),
        "SKI_CA_PRIVATE_KEY": str(tmp_path / "user_ca"),
        "SKI_CA_PUBLIC_KEY": str(tmp_path / "user_ca.pub"),
        "SKI_CA_KRL": str(tmp_path / "revoked.krl"),
        "ORDINARY_CERT_EXTENSIONS": "pty",
    }
