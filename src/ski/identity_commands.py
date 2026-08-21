"""Application workflows for read-only demo identity commands."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from ski.configuration import load_runtime_configuration
from ski.identities import SqliteIdentityStore, UserDetail, UserSummary
from ski.state import StateDatabase


@dataclass(frozen=True, slots=True)
class IdentityReadResources:
    """Resources held for one short read-only identity workflow."""

    database: StateDatabase
    store: SqliteIdentityStore


@contextmanager
def identity_read_resources() -> Iterator[IdentityReadResources]:
    """Open and always close the configured identity resources."""
    configuration = load_runtime_configuration(
        bind="127.0.0.1",
        port=22,
        require_ordinary_ca=False,
    )
    database = StateDatabase.open(configuration.database)
    try:
        yield IdentityReadResources(database, SqliteIdentityStore(database))
    finally:
        database.close()


def show_user(username: str) -> UserDetail:
    """Load one credential-free user detail view."""
    with identity_read_resources() as resources:
        return resources.store.get_user_detail(username)


def list_users() -> tuple[UserSummary, ...]:
    """Load all credential-free user summaries in stable order."""
    with identity_read_resources() as resources:
        return resources.store.list_users()
