"""Validated, immutable runtime configuration."""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from dotenv import dotenv_values

from ski.environment import SYSTEM_ENVIRONMENT_FILE, find_environment_file

CERTIFICATE_LIFETIME = 25 * 60 * 60
ORDINARY_CERTIFICATE_EXTENSIONS = frozenset(
    {
        "pty",
        "agent-forwarding",
        "port-forwarding",
        "x11-forwarding",
        "user-rc",
    },
)


class ConfigurationError(ValueError):
    """Raised when service configuration cannot be used safely."""


@dataclass(frozen=True)
class RuntimeConfiguration:
    """The complete configuration snapshot used by a service instance."""

    bind: str
    port: int
    database: Path
    ca_private_key: Path | None
    ca_public_key: Path | None
    ca_krl: Path | None
    ordinary_extensions: tuple[str, ...]
    certificate_lifetime: int
    environment_file: Path | None
    values: Mapping[str, str]


def _validate_bind(bind: str) -> str:
    if bind == "*":
        return bind
    try:
        ipaddress.ip_address(bind)
    except ValueError as exc:
        raise ConfigurationError("SKI_BIND must be an IPv4 or IPv6 address") from exc
    return bind


def _validate_port(port: int, *, allow_ephemeral: bool = False) -> int:
    minimum = 0 if allow_ephemeral else 1
    if not minimum <= port <= 65535:
        raise ConfigurationError("SKI_PORT must be between 1 and 65535")
    return port


def _validate_database(value: str | None) -> Path:
    if not value:
        raise ConfigurationError("SKI_CA_DATABASE is required")
    database = Path(value).expanduser()
    if database.name in {"", ".", ".."}:
        raise ConfigurationError("SKI_CA_DATABASE must name a file")
    parent = database.parent
    if not parent.is_dir():
        raise ConfigurationError("SKI_CA_DATABASE parent directory is unavailable")
    if not os.access(parent, os.W_OK):
        raise ConfigurationError("SKI_CA_DATABASE parent directory is not writable")
    return database


def _validate_output_path(value: str | None, variable: str) -> Path:
    if not value:
        raise ConfigurationError(f"{variable} is required")
    path = Path(value).expanduser()
    if path.name in {"", ".", ".."}:
        raise ConfigurationError(f"{variable} must name a file")
    if not path.parent.is_dir():
        raise ConfigurationError(f"{variable} parent directory is unavailable")
    if not os.access(path.parent, os.W_OK):
        raise ConfigurationError(f"{variable} parent directory is not writable")
    return path


def _parse_ordinary_extensions(value: str | None) -> tuple[str, ...]:
    if not value or not value.strip():
        raise ConfigurationError("ORDINARY_CERT_EXTENSIONS is required")
    extensions = tuple(item.strip() for item in value.split(","))
    if any(not item for item in extensions):
        raise ConfigurationError("ORDINARY_CERT_EXTENSIONS contains an empty value")
    if len(set(extensions)) != len(extensions):
        raise ConfigurationError("ORDINARY_CERT_EXTENSIONS contains a duplicate")
    unsupported = set(extensions) - ORDINARY_CERTIFICATE_EXTENSIONS
    if unsupported:
        raise ConfigurationError(
            "ORDINARY_CERT_EXTENSIONS contains an unsupported value"
        )
    return extensions


def load_runtime_configuration(
    *,
    bind: str,
    port: int,
    exported_environment: Mapping[str, str] | None = None,
    directory: Path | None = None,
    home_directory: Path | None = None,
    system_file: Path = SYSTEM_ENVIRONMENT_FILE,
    allow_ephemeral_port: bool = False,
    require_ordinary_ca: bool = True,
) -> RuntimeConfiguration:
    """Load and validate one service configuration without side effects."""
    exported = dict(
        os.environ if exported_environment is None else exported_environment,
    )
    selected_home = home_directory
    if selected_home is None:
        selected_home = Path(exported.get("HOME", str(Path.home())))
    environment_file = find_environment_file(
        directory=directory,
        home_directory=selected_home,
        system_file=system_file,
    )

    values: dict[str, str] = {}
    if environment_file is not None:
        for key, value in dotenv_values(environment_file).items():
            if value is not None:
                values[key] = value
    values.update(exported)

    validated_bind = _validate_bind(bind)
    validated_port = _validate_port(port, allow_ephemeral=allow_ephemeral_port)
    database = _validate_database(values.get("SKI_CA_DATABASE"))
    if require_ordinary_ca:
        ca_private_key = _validate_output_path(
            values.get("SKI_CA_PRIVATE_KEY"),
            "SKI_CA_PRIVATE_KEY",
        )
        ca_public_key = _validate_output_path(
            values.get("SKI_CA_PUBLIC_KEY"),
            "SKI_CA_PUBLIC_KEY",
        )
        ca_krl = _validate_output_path(values.get("SKI_CA_KRL"), "SKI_CA_KRL")
        ordinary_extensions = _parse_ordinary_extensions(
            values.get("ORDINARY_CERT_EXTENSIONS"),
        )
    else:
        ca_private_key = None
        ca_public_key = None
        ca_krl = None
        ordinary_extensions = ()
    return RuntimeConfiguration(
        bind=validated_bind,
        port=validated_port,
        database=database,
        ca_private_key=ca_private_key,
        ca_public_key=ca_public_key,
        ca_krl=ca_krl,
        ordinary_extensions=ordinary_extensions,
        certificate_lifetime=CERTIFICATE_LIFETIME,
        environment_file=environment_file,
        values=MappingProxyType(values),
    )
