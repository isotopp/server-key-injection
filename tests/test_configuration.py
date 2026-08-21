"""Behavioural tests for service configuration snapshots."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from ski.configuration import ConfigurationError, load_runtime_configuration


def test_runtime_configuration_uses_first_file_and_exported_values(
    tmp_path: Path,
) -> None:
    """The first environment file is merged below the exported baseline."""
    local_file = tmp_path / ".env"
    local_file.write_text(
        "SKI_CA_DATABASE=from-file.sqlite3\nSKI_CONFIG_MARKER=local\n",
    )
    home_directory = tmp_path / "home"
    home_directory.mkdir()
    (home_directory / ".ski.env").write_text(
        "SKI_CA_DATABASE=from-home.sqlite3\n"
        f"SKI_CA_PRIVATE_KEY={tmp_path / 'home-ca'}\n"
        f"SKI_CA_PUBLIC_KEY={tmp_path / 'home-ca.pub'}\n"
        f"SKI_CA_KRL={tmp_path / 'home.krl'}\n"
        "ORDINARY_CERT_EXTENSIONS=pty\nSKI_CONFIG_MARKER=home\n",
    )
    system_file = tmp_path / "etc" / "ski" / "env"
    system_file.parent.mkdir(parents=True)
    system_file.write_text("SKI_CONFIG_MARKER=system\n")

    config = load_runtime_configuration(
        bind="127.0.0.1",
        port=2222,
        directory=tmp_path,
        home_directory=home_directory,
        system_file=system_file,
        exported_environment={
            "HOME": str(home_directory),
            "SKI_CA_DATABASE": "from-shell.sqlite3",
            "SKI_CA_PRIVATE_KEY": str(tmp_path / "shell-ca"),
            "SKI_CA_PUBLIC_KEY": str(tmp_path / "shell-ca.pub"),
            "SKI_CA_KRL": str(tmp_path / "shell.krl"),
            "ORDINARY_CERT_EXTENSIONS": "pty",
        },
    )

    assert config.database == Path("from-shell.sqlite3")
    assert config.environment_file == local_file
    assert config.values["SKI_CONFIG_MARKER"] == "local"
    assert config.bind == "127.0.0.1"
    assert config.port == 2222


def test_runtime_configuration_loads_ordinary_ca_contract(tmp_path: Path) -> None:
    """A complete environment exposes the fixed ordinary CA policy."""
    exported = {
        "SKI_CA_DATABASE": str(tmp_path / "state.sqlite3"),
        "SKI_CA_PRIVATE_KEY": str(tmp_path / "keys" / "user_ca"),
        "SKI_CA_PUBLIC_KEY": str(tmp_path / "keys" / "user_ca.pub"),
        "SKI_CA_KRL": str(tmp_path / "revoked.krl"),
        "ORDINARY_CERT_EXTENSIONS": "pty, port-forwarding",
    }
    (tmp_path / "keys").mkdir()

    config = load_runtime_configuration(
        bind="127.0.0.1",
        port=2222,
        exported_environment=exported,
        directory=tmp_path,
        home_directory=tmp_path,
    )

    assert config.ca_private_key == tmp_path / "keys" / "user_ca"
    assert config.ca_public_key == tmp_path / "keys" / "user_ca.pub"
    assert config.ca_krl == tmp_path / "revoked.krl"
    assert config.ordinary_extensions == ("pty", "port-forwarding")
    assert config.certificate_lifetime == 25 * 60 * 60


def test_runtime_configuration_rejects_unsupported_extension_without_echo(
    tmp_path: Path,
) -> None:
    """Unknown extension policy fails without disclosing the configured value."""
    (tmp_path / "keys").mkdir()
    secret_value = "SECRET_EXTENSION_MARKER"
    environment = {
        "SKI_CA_DATABASE": str(tmp_path / "state.sqlite3"),
        "SKI_CA_PRIVATE_KEY": str(tmp_path / "keys" / "user_ca"),
        "SKI_CA_PUBLIC_KEY": str(tmp_path / "keys" / "user_ca.pub"),
        "SKI_CA_KRL": str(tmp_path / "revoked.krl"),
        "ORDINARY_CERT_EXTENSIONS": f"pty,{secret_value}",
    }

    with pytest.raises(ConfigurationError, match="unsupported value") as error:
        load_runtime_configuration(
            bind="127.0.0.1",
            port=2222,
            exported_environment=environment,
            directory=tmp_path,
            home_directory=tmp_path,
        )

    assert secret_value not in str(error.value)


@pytest.mark.parametrize(
    "missing",
    [
        "SKI_CA_PRIVATE_KEY",
        "SKI_CA_PUBLIC_KEY",
        "SKI_CA_KRL",
        "ORDINARY_CERT_EXTENSIONS",
    ],
)
def test_runtime_configuration_requires_every_ordinary_ca_setting(
    tmp_path: Path,
    missing: str,
) -> None:
    """Missing ordinary-CA settings fail with the setting name only."""
    (tmp_path / "keys").mkdir()
    environment = {
        "SKI_CA_DATABASE": str(tmp_path / "state.sqlite3"),
        "SKI_CA_PRIVATE_KEY": str(tmp_path / "keys" / "user_ca"),
        "SKI_CA_PUBLIC_KEY": str(tmp_path / "keys" / "user_ca.pub"),
        "SKI_CA_KRL": str(tmp_path / "revoked.krl"),
        "ORDINARY_CERT_EXTENSIONS": "pty",
    }
    environment.pop(missing)

    with pytest.raises(ConfigurationError, match=missing):
        load_runtime_configuration(
            bind="127.0.0.1",
            port=2222,
            exported_environment=environment,
            directory=tmp_path,
            home_directory=tmp_path,
        )


@pytest.mark.parametrize("extensions", ["pty,,agent-forwarding", "pty,pty"])
def test_runtime_configuration_rejects_malformed_extension_policy(
    tmp_path: Path,
    extensions: str,
) -> None:
    """Empty and duplicate extension entries fail without opening state."""
    (tmp_path / "keys").mkdir()
    environment = {
        "SKI_CA_DATABASE": str(tmp_path / "state.sqlite3"),
        "SKI_CA_PRIVATE_KEY": str(tmp_path / "keys" / "user_ca"),
        "SKI_CA_PUBLIC_KEY": str(tmp_path / "keys" / "user_ca.pub"),
        "SKI_CA_KRL": str(tmp_path / "revoked.krl"),
        "ORDINARY_CERT_EXTENSIONS": extensions,
    }

    with pytest.raises(ConfigurationError):
        load_runtime_configuration(
            bind="127.0.0.1",
            port=2222,
            exported_environment=environment,
            directory=tmp_path,
            home_directory=tmp_path,
        )


def test_runtime_configuration_rejects_unavailable_ca_parent_without_echo(
    tmp_path: Path,
) -> None:
    """Output paths cannot create missing parent directories during validation."""
    marker = "private-ca-parent-marker"
    environment = {
        "SKI_CA_DATABASE": str(tmp_path / "state.sqlite3"),
        "SKI_CA_PRIVATE_KEY": str(tmp_path / marker / "user_ca"),
        "SKI_CA_PUBLIC_KEY": str(tmp_path / "user_ca.pub"),
        "SKI_CA_KRL": str(tmp_path / "revoked.krl"),
        "ORDINARY_CERT_EXTENSIONS": "pty",
    }

    with pytest.raises(ConfigurationError, match="parent directory") as error:
        load_runtime_configuration(
            bind="127.0.0.1",
            port=2222,
            exported_environment=environment,
            directory=tmp_path,
            home_directory=tmp_path,
        )

    assert marker not in str(error.value)


def test_runtime_configuration_is_immutable(tmp_path: Path) -> None:
    """Callers cannot change a configuration after it is loaded."""
    database = tmp_path / "state.sqlite3"
    config = load_runtime_configuration(
        bind="127.0.0.1",
        port=2222,
        exported_environment={
            "SKI_CA_DATABASE": str(database),
            "SKI_CA_PRIVATE_KEY": str(tmp_path / "ca"),
            "SKI_CA_PUBLIC_KEY": str(tmp_path / "ca.pub"),
            "SKI_CA_KRL": str(tmp_path / "ca.krl"),
            "ORDINARY_CERT_EXTENSIONS": "pty",
        },
        directory=tmp_path,
        home_directory=tmp_path,
    )

    with pytest.raises(TypeError):
        cast(Any, config.values)["SKI_CA_DATABASE"] = "other.sqlite3"
    with pytest.raises(AttributeError):
        setattr(config, "port", 2200)


@pytest.mark.parametrize(
    ("bind", "port", "environment", "message"),
    [
        ("127.0.0.1", 2222, {}, "SKI_CA_DATABASE"),
        ("127.0.0.1", 0, {"SKI_CA_DATABASE": "state.sqlite3"}, "SKI_PORT"),
        ("issuer.example", 2222, {"SKI_CA_DATABASE": "state.sqlite3"}, "SKI_BIND"),
    ],
)
def test_invalid_runtime_configuration_is_rejected(
    tmp_path: Path,
    bind: str,
    port: int,
    environment: dict[str, str],
    message: str,
) -> None:
    """Invalid required settings fail before a service can start."""
    with pytest.raises(ConfigurationError, match=message):
        load_runtime_configuration(
            bind=bind,
            port=port,
            exported_environment=environment,
            directory=tmp_path,
            home_directory=tmp_path,
        )


def test_dotenv_example_documents_database_backed_host_key() -> None:
    """The example does not offer a host-key environment override."""
    example = (Path(__file__).parents[1] / "docs" / "dotenv.example").read_text()

    assert "SKI_CA_DATABASE=" in example
    assert "stores its" in example
    assert "SKI_HOST_KEY" not in example
    assert "SKI_CA_HOST_KEY" not in example
