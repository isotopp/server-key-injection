"""Loading configuration from the supported ski environment files."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

SYSTEM_ENVIRONMENT_FILE = Path("/home/ski/etc/env")


def find_environment_file(
    *,
    directory: Path | None = None,
    home_directory: Path | None = None,
    system_file: Path = SYSTEM_ENVIRONMENT_FILE,
) -> Path | None:
    """Return the first available environment file in the documented order."""
    current_directory = directory if directory is not None else Path.cwd()
    home = home_directory if home_directory is not None else Path(os.environ["HOME"])

    for candidate in (current_directory / ".env", home / ".ski.env", system_file):
        if candidate.is_file():
            return candidate

    return None


def load_environment() -> Path | None:
    """Load the first available environment file without overriding exports."""
    environment_file = find_environment_file()
    if environment_file is not None:
        load_dotenv(environment_file, override=False)

    return environment_file
