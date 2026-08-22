# `ski` documentation

These guides describe the issuer proof of concept and the separately installed
offline host authorizer. They are operational documentation, not a substitute
for the installing organization's identity, configuration-management,
monitoring, SELinux, incident-response, or production-assurance controls.

| Guide | Audience | Purpose |
| --- | --- | --- |
| [INSTALLATION.md](INSTALLATION.md) | Issuer operator | Clone, install, initialize, and create the first SQLite demo identity. |
| [OPERATION.md](OPERATION.md) | Issuer operator and end user | Daily service operation, maintenance, certificate issuance, and agent workflow. |
| [TARGET-HOST.md](TARGET-HOST.md) | Production-host operator | Install `ski-authorize`, trust the public CA, and configure offline OpenSSH authorization. |
| [systemd/INSTALLATION.md](systemd/INSTALLATION.md) | Issuer deployment operator | Install and supervise the issuer with systemd and journald. |

The issuer runs on the corporate office side. A production host receives only
the public CA material, local authorization policy, and separately installed
host helper. It does not contact the issuer or identity store during login.

KRL and CA-rotation instructions are added only when the corresponding Epic 6
commands and behavior are implemented. Until then, the guides label those
operations as pending rather than presenting speculative commands.

## Final handoff check

Before adopting the proof of concept, follow the links above and compare every
command example with the installed revision's `ski --help`, `ski ca --help`,
and `ski-authorize --help`. Confirm that the target host's public CA, local
policy, file ownership, OpenSSH version, and SELinux posture have been reviewed
by the installing organization. The documentation is evidence of the intended
boundary; it does not replace that organization's identity integration,
configuration management, monitoring, incident response, or production review.
