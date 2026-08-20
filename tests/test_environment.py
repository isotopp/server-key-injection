"""Behaviour for locating ski environment files."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ski.environment import find_environment_file, load_environment


def test_local_environment_file_takes_precedence(
    tmp_path: Path,
) -> None:
    """The working-directory .env wins over all fallback files."""
    local_file = tmp_path / ".env"
    local_file.write_text("SOURCE=local\n")

    home_file = tmp_path / "home" / ".ski.env"
    home_file.parent.mkdir()
    home_file.write_text("SOURCE=home\n")

    system_file = tmp_path / "etc" / "ski" / "env"
    system_file.parent.mkdir(parents=True)
    system_file.write_text("SOURCE=system\n")

    assert (
        find_environment_file(
            directory=tmp_path,
            home_directory=home_file.parent,
            system_file=system_file,
        )
        == local_file
    )


def test_home_environment_file_is_used_when_no_local_file_exists(
    tmp_path: Path,
) -> None:
    """The user's file is the first fallback after the working directory."""
    home_file = tmp_path / "home" / ".ski.env"
    home_file.parent.mkdir()
    home_file.write_text("SOURCE=home\n")

    system_file = tmp_path / "etc" / "ski" / "env"
    system_file.parent.mkdir(parents=True)
    system_file.write_text("SOURCE=system\n")

    assert (
        find_environment_file(
            directory=tmp_path,
            home_directory=home_file.parent,
            system_file=system_file,
        )
        == home_file
    )


def test_loader_loads_only_the_first_available_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Loading stops at .env and does not replace an exported value."""
    local_file = tmp_path / ".env"
    local_file.write_text("FROM_SKI=local\nEXPORTED=from-file\n")

    home_directory = tmp_path / "home"
    home_directory.mkdir()
    (home_directory / ".ski.env").write_text("FROM_SKI=home\n")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HOME", str(home_directory))
    monkeypatch.setenv("EXPORTED", "from-shell")

    assert load_environment() == local_file
    assert os.environ["FROM_SKI"] == "local"
    assert os.environ["EXPORTED"] == "from-shell"
