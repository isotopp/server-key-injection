"""Shared test configuration helpers."""

from __future__ import annotations

from pathlib import Path

from ski.ca import CAFileWriter
from ski.state import StateDatabase


def runtime_environment(tmp_path: Path, database: Path) -> dict[str, str]:
    """Return a complete runtime environment with a test persistent CA."""
    environment = {
        "SKI_CA_DATABASE": str(database),
        "SKI_CA_PRIVATE_KEY": str(tmp_path / "user_ca"),
        "SKI_CA_PUBLIC_KEY": str(tmp_path / "user_ca.pub"),
        "SKI_CA_KRL": str(tmp_path / "revoked.krl"),
        "ORDINARY_CERT_EXTENSIONS": "pty",
    }
    state = StateDatabase.open(database, owner=True)
    try:
        if state.get_active_ca() is None:
            material = CAFileWriter().install(
                private_path=tmp_path / "user_ca",
                public_path=tmp_path / "user_ca.pub",
                krl_path=tmp_path / "revoked.krl",
            )
            state.initialize_active_ca(
                public_key=material.public_bytes,
                fingerprint=material.fingerprint,
                private_key_path=tmp_path / "user_ca",
                request_id="test-ca-init",
            )
    finally:
        state.close()
    return environment
