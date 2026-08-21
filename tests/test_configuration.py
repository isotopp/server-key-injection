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
        "SKI_CA_DATABASE=from-home.sqlite3\nSKI_CONFIG_MARKER=home\n",
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
        },
    )

    assert config.database == Path("from-shell.sqlite3")
    assert config.environment_file == local_file
    assert config.values["SKI_CONFIG_MARKER"] == "local"
    assert config.bind == "127.0.0.1"
    assert config.port == 2222


def test_runtime_configuration_is_immutable(tmp_path: Path) -> None:
    """Callers cannot change a configuration after it is loaded."""
    database = tmp_path / "state.sqlite3"
    config = load_runtime_configuration(
        bind="127.0.0.1",
        port=2222,
        exported_environment={"SKI_CA_DATABASE": str(database)},
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
