"""Offline parsing of the OpenSSH certificate attributes used by policy."""

from __future__ import annotations

import base64
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

import asyncssh


class CertificateError(ValueError):
    """Raised when offered SSH-certificate input is unsupported or malformed."""


@dataclass(frozen=True, slots=True)
class CertificateAttributes:
    """Safe certificate fields needed by the host authorization decision."""

    algorithm: str
    ca_algorithm: str
    ca_fingerprint: str
    key_id: str
    principals: tuple[str, ...]
    serial: int
    valid_after: int
    valid_before: int


def _string(data: bytes, offset: int) -> tuple[bytes, int]:
    """Read one SSH wire-format string."""
    if offset + 4 > len(data):
        raise CertificateError("certificate data is truncated")
    length = struct.unpack_from(">I", data, offset)[0]
    offset += 4
    end = offset + length
    if end > len(data):
        raise CertificateError("certificate data is truncated")
    return data[offset:end], end


def _number(data: bytes, offset: int, size: int) -> tuple[int, int]:
    """Read one unsigned SSH wire-format integer."""
    end = offset + size
    if end > len(data):
        raise CertificateError("certificate data is truncated")
    if size == 8:
        return struct.unpack_from(">Q", data, offset)[0], end
    return struct.unpack_from(">I", data, offset)[0], end


def _text(value: bytes, label: str) -> str:
    """Decode one certificate text field."""
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CertificateError(f"certificate {label} is not text") from exc


def _parse_public_data(
    data: bytes,
) -> tuple[str, str, int, tuple[str, ...], int, int]:
    """Extract OpenSSH user-certificate fields from its public wire data."""
    offset = 0
    algorithm_bytes, offset = _string(data, offset)
    algorithm = _text(algorithm_bytes, "algorithm")
    if algorithm != "ssh-ed25519-cert-v01@openssh.com":
        raise CertificateError("certificate algorithm is unsupported")

    _nonce, offset = _string(data, offset)
    _user_public_key, offset = _string(data, offset)
    serial, offset = _number(data, offset, 8)
    certificate_type, offset = _number(data, offset, 4)
    if certificate_type != 1:
        raise CertificateError("certificate is not a user certificate")

    key_id_bytes, offset = _string(data, offset)
    key_id = _text(key_id_bytes, "key ID")
    principal_data, offset = _string(data, offset)
    principals: list[str] = []
    principal_offset = 0
    while principal_offset < len(principal_data):
        principal_bytes, principal_offset = _string(principal_data, principal_offset)
        principals.append(_text(principal_bytes, "principal"))
    if principal_offset != len(principal_data):
        raise CertificateError("certificate principals are malformed")

    valid_after, offset = _number(data, offset, 8)
    valid_before, offset = _number(data, offset, 8)
    _critical_options, offset = _string(data, offset)
    _extensions, offset = _string(data, offset)
    _reserved, offset = _string(data, offset)
    _signature_key, offset = _string(data, offset)
    _signature, offset = _string(data, offset)
    if offset != len(data):
        raise CertificateError("certificate data has trailing bytes")

    return (
        algorithm,
        key_id,
        serial,
        tuple(principals),
        valid_after,
        valid_before,
    )


def parse_certificate(
    certificate_type: str,
    certificate_base64: str,
    *,
    clock: Callable[[], float] = time.time,
) -> CertificateAttributes:
    """Parse one OpenSSH certificate supplied as type plus base64 body."""
    if certificate_type != "ssh-ed25519-cert-v01@openssh.com":
        raise CertificateError("certificate type is unsupported")
    if not isinstance(certificate_base64, str) or not certificate_base64:
        raise CertificateError("certificate body is malformed")
    if any(character.isspace() for character in certificate_base64):
        raise CertificateError("certificate body is malformed")
    try:
        public_data = base64.b64decode(certificate_base64, validate=True)
        encoded = f"{certificate_type} {certificate_base64}"
        certificate = asyncssh.import_certificate(encoded)
    except (ValueError, UnicodeError, asyncssh.KeyImportError) as exc:
        raise CertificateError("certificate body is malformed") from exc

    if not isinstance(certificate, asyncssh.SSHCertificate):
        raise CertificateError("certificate body is not a certificate")
    try:
        (
            algorithm,
            key_id,
            serial,
            principals,
            valid_after,
            valid_before,
        ) = _parse_public_data(public_data)
        signing_key = cast(Any, certificate).signing_key
        ca_algorithm = signing_key.get_algorithm()
        ca_fingerprint = signing_key.get_fingerprint()
    except (AttributeError, TypeError, ValueError) as exc:
        raise CertificateError("certificate attributes are malformed") from exc

    if ca_algorithm != "ssh-ed25519":
        raise CertificateError("certificate CA algorithm is unsupported")
    now = int(clock())
    if now < valid_after or now >= valid_before:
        raise CertificateError("certificate is not currently time-valid")

    return CertificateAttributes(
        algorithm=algorithm,
        ca_algorithm=ca_algorithm,
        ca_fingerprint=ca_fingerprint,
        key_id=key_id,
        principals=principals,
        serial=serial,
        valid_after=valid_after,
        valid_before=valid_before,
    )
