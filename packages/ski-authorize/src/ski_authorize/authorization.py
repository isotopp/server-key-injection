"""Pure, offline authorization decisions for an OpenSSH user certificate."""

from __future__ import annotations

import re

from .certificate import CertificateAttributes
from .policy import HostPolicy


class AuthorizationDenied(ValueError):
    """Raised when a certificate cannot authorize the requested account."""


_ACCOUNT_PATTERN = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
_GROUP_PRINCIPAL_PATTERN = re.compile(r"group:[a-z][a-z0-9-]{0,62}\Z")


def _require_account(value: str, label: str) -> None:
    if not isinstance(value, str) or _ACCOUNT_PATTERN.fullmatch(value) is None:
        raise AuthorizationDenied(f"{label} is not canonical")


def authorize_certificate(
    policy: HostPolicy,
    certificate: CertificateAttributes,
    *,
    supplied_ca_fingerprint: str,
    target_user: str,
) -> str:
    """Return the first allowed group principal, or deny the request.

    All inputs are already local value objects.  This function deliberately
    performs no I/O, environment lookup, account lookup, or mutable caching.
    """
    if not policy.allow_self_login_only:
        raise AuthorizationDenied("self-login policy is disabled")
    if (
        supplied_ca_fingerprint != policy.trusted_ca_fingerprint
        or certificate.ca_fingerprint != policy.trusted_ca_fingerprint
    ):
        raise AuthorizationDenied("certificate CA fingerprint is not trusted")

    _require_account(target_user, "target account")
    _require_account(certificate.key_id, "certificate key ID")
    if certificate.key_id != target_user:
        raise AuthorizationDenied("certificate key ID does not match target account")

    principals = certificate.principals
    if not principals or principals[0] != target_user:
        raise AuthorizationDenied("certificate identity principal does not match")
    if len(set(principals)) != len(principals):
        raise AuthorizationDenied("certificate principals are duplicated")

    groups = principals[1:]
    if not groups or any(
        _GROUP_PRINCIPAL_PATTERN.fullmatch(group) is None for group in groups
    ):
        raise AuthorizationDenied("certificate group principals are malformed")
    allowed = set(policy.allowed_groups)
    permitted = sorted(set(groups) & allowed)
    if not permitted:
        raise AuthorizationDenied("certificate has no allowed group")
    return permitted[0]
