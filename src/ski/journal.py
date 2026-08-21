"""Structured operational events and journal sinks."""

from __future__ import annotations

import importlib
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, TextIO

_ALLOWED_APPLICATION_FIELDS = frozenset(
    {
        "SKI_ADDRESSES",
        "SKI_BIND",
        "SKI_CERTIFICATE_SERIAL",
        "SKI_CONFIG_GENERATION",
        "SKI_DECISION",
        "SKI_ERROR_CODE",
        "SKI_GROUPS",
        "SKI_IDENTITY",
        "SKI_PORT",
        "SKI_REASON",
        "SKI_REQUEST_ID",
    },
)


@dataclass(frozen=True)
class Event:
    """One operational event independent of its delivery mechanism."""

    name: str
    message: str
    priority: int
    fields: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        fields = dict(self.fields)
        unsupported = set(fields) - _ALLOWED_APPLICATION_FIELDS
        if unsupported:
            names = ", ".join(sorted(unsupported))
            raise ValueError(f"unsupported journal field(s): {names}")
        object.__setattr__(self, "fields", MappingProxyType(fields))


class MemoryEventSink:
    """Collect events for tests and local runtime composition."""

    def __init__(self) -> None:
        self.events: list[Event] = []

    def emit(self, event: Event) -> None:
        self.events.append(event)


class ConsoleEventSink:
    """Write a minimal event representation for non-systemd development."""

    def __init__(self, *, stream: TextIO | None = None) -> None:
        self._stream = sys.stderr if stream is None else stream

    def emit(self, event: Event) -> None:
        print(f"{event.name}: {event.message}", file=self._stream, flush=True)


class JournalEventSink:
    """Submit events to the native systemd journal API."""

    def __init__(self, *, journal: Any | None = None, identifier: str = "ski") -> None:
        if journal is None:
            journal = importlib.import_module("systemd.journal")
        self._journal = journal
        self._identifier = identifier

    def emit(self, event: Event) -> None:
        fields: dict[str, str | int] = {
            "PRIORITY": event.priority,
            "SYSLOG_IDENTIFIER": self._identifier,
            "SKI_EVENT": event.name,
        }
        fields.update(event.fields)
        self._journal.send(event.message, **fields)
