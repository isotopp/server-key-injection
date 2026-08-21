"""Behavioural tests for the operational event boundary."""

from __future__ import annotations

from io import StringIO

import pytest

from ski.journal import ConsoleEventSink, Event, JournalEventSink, MemoryEventSink


def test_memory_event_sink_records_a_structured_service_event() -> None:
    """A caller can observe one complete operational event."""
    sink = MemoryEventSink()
    sink.emit(
        Event(
            name="service_ready",
            message="ski is ready",
            priority=6,
            fields={"SKI_REQUEST_ID": "request-1"},
        ),
    )

    assert sink.events[0].name == "service_ready"
    assert sink.events[0].message == "ski is ready"
    assert sink.events[0].priority == 6
    assert sink.events[0].fields["SKI_REQUEST_ID"] == "request-1"


def test_journal_sink_submits_native_queryable_fields() -> None:
    """The production boundary passes fields instead of embedding JSON."""

    class FakeJournal:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, str | int]]] = []

        def send(self, message: str, **fields: str | int) -> None:
            self.calls.append((message, fields))

    journal = FakeJournal()
    sink = JournalEventSink(journal=journal, identifier="ski")
    sink.emit(
        Event(
            name="service_ready",
            message="ski is ready",
            priority=6,
            fields={"SKI_REQUEST_ID": "request-1"},
        ),
    )

    message, fields = journal.calls[0]
    assert message == "ski is ready"
    assert fields == {
        "PRIORITY": 6,
        "SYSLOG_IDENTIFIER": "ski",
        "SKI_EVENT": "service_ready",
        "SKI_REQUEST_ID": "request-1",
    }


def test_event_rejects_unapproved_application_fields() -> None:
    """The event API cannot be used as a secret dumping channel."""
    with pytest.raises(ValueError, match="unsupported journal field"):
        Event(
            name="service_ready",
            message="ski is ready",
            priority=6,
            fields={"PASSWORD": "secret"},
        )

    with pytest.raises(ValueError, match="unsupported journal field"):
        Event(
            name="service_ready",
            message="ski is ready",
            priority=6,
            fields={"SKI_PRIVATE_KEY": "secret"},
        )


def test_console_sink_is_available_without_systemd() -> None:
    """Non-systemd development has an explicit, redacted fallback sink."""
    output = StringIO()
    sink = ConsoleEventSink(stream=output)
    sink.emit(Event(name="service_ready", message="ski is ready", priority=6))

    assert output.getvalue() == "service_ready: ski is ready\n"


def test_request_events_are_redacted_across_console_and_journal_sinks() -> None:
    """Safe request metadata is delivered without credential or agent payloads."""

    class FakeJournal:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, str | int]]] = []

        def send(self, message: str, **fields: str | int) -> None:
            self.calls.append((message, fields))

    secret_values = {
        "super-secret-password",
        "JBSWY3DPEHPK3PXP",
        "$argon2id$v=19$m=65536$verifier",
        "-----BEGIN PRIVATE KEY-----",
        "agent-payload-bytes",
        "FULL_ENVIRONMENT_MARKER",
    }
    event = Event(
        name="certificate_request_completed",
        message="certificate request completed",
        priority=6,
        fields={
            "SKI_REQUEST_ID": "request-1",
            "SKI_IDENTITY": "alice",
            "SKI_DECISION": "allow",
            "SKI_GROUPS": "platform-ops",
        },
    )

    console_output = StringIO()
    ConsoleEventSink(stream=console_output).emit(event)
    journal = FakeJournal()
    JournalEventSink(journal=journal).emit(event)

    rendered = repr((console_output.getvalue(), journal.calls))
    for secret in secret_values:
        assert secret not in rendered
    assert set(journal.calls[0][1]) == {
        "PRIORITY",
        "SYSLOG_IDENTIFIER",
        "SKI_EVENT",
        "SKI_REQUEST_ID",
        "SKI_IDENTITY",
        "SKI_DECISION",
        "SKI_GROUPS",
    }
