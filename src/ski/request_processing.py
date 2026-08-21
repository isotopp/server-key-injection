"""Application processing for authenticated certificate requests."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from typing import Any, Protocol

import asyncssh

from ski.identities import IdentitySnapshot
from ski.injection import OrdinaryAgentInjector
from ski.journal import Event


class RequestEventSink(Protocol):
    """Minimal safe event boundary required by request processing."""

    def emit(self, event: Event) -> None:
        """Accept one already-redacted service event."""


class AuthenticatedRequestProcessor:
    """Run one authenticated issuance request within an admitted scope."""

    def __init__(
        self,
        ordinary_injector: OrdinaryAgentInjector,
        *,
        event_sink: RequestEventSink,
        request_scope: Callable[[], Any],
    ) -> None:
        self._ordinary_injector = ordinary_injector
        self._event_sink = event_sink
        self._request_scope = request_scope

    async def handle(
        self,
        connection: asyncssh.SSHServerConnection,
        identity: IdentitySnapshot,
    ) -> str:
        """Issue and inject one credential, emitting only safe outcomes."""
        request_id = secrets.token_hex(16)
        groups = ",".join(identity.groups) or "(none)"
        fields = {
            "SKI_REQUEST_ID": request_id,
            "SKI_IDENTITY": identity.username,
            "SKI_DECISION": "allow",
            "SKI_GROUPS": groups,
        }
        try:
            async with self._request_scope():
                issuance = await self._ordinary_injector.handle(
                    connection,
                    identity,
                    request_id=request_id,
                )
                fields["SKI_CERTIFICATE_SERIAL"] = str(issuance.record.serial)
                result = (
                    f"{identity.username} serial={issuance.record.serial} "
                    f"valid-until={issuance.record.valid_before}"
                )
        except Exception as exc:
            self._emit(
                "certificate_request_failed",
                "certificate request failed",
                fields={
                    **fields,
                    "SKI_DECISION": "deny",
                    "SKI_ERROR_CODE": type(exc).__name__,
                },
                priority=4,
            )
            raise
        self._emit(
            "certificate_request_completed",
            "certificate request completed",
            fields=fields,
        )
        return result

    def _emit(
        self,
        name: str,
        message: str,
        *,
        fields: dict[str, str],
        priority: int = 6,
    ) -> None:
        """Emit one event through the explicit redacted sink boundary."""
        self._event_sink.emit(
            Event(
                name=name,
                message=message,
                priority=priority,
                fields=fields,
            ),
        )
