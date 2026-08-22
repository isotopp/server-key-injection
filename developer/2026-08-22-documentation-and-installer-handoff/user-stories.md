# Documentation and installer handoff

## Epic outcome

Complete the `ski` proof of concept with accurate, internally consistent
operator and user documentation in `docs/`. The documentation must make a
clean distinction between the functionality supplied by this repository and
the controls an adopting organization must design, deploy, operate, and review
for itself.

This is Epic 8 — Documentation and installer handoff from the architecture.
It follows Epic 6: documentation of KRL materialization and CA rotation must
describe only the commands and behavior actually delivered by that epic.

## Scope and boundaries

This epic changes Markdown files under `docs/` only. It may add a small
documentation index under `docs/` if that makes the handoff clearer.

It does not change application code, package metadata, tests, example package
assets, systemd units, install scripts, OpenSSH configuration, or README files
outside `docs/`. It does not add an identity-provider integration, a
configuration-management client, monitoring or alerting code, a SELinux module
or local policy, a backup/restore tool, VM automation, or new integration or
security-regression tests.

Every command or behavior described as provided by `ski` must be implemented
at the time the documentation is written. Installer-owned work must be named
as such rather than presented as a missing setup step which this project will
later automate.

## User stories

### US-1: Give the issuer operator one accurate lifecycle guide

As an issuer operator, I can find the installation, daily-operation, and
recovery boundaries for the SQLite proof of concept, so that I know which CA,
database, KRL, systemd, and time-synchronization responsibilities belong to
me.

**Acceptance criteria:**

- `docs/` clearly directs an operator from installation to the authoritative
  operational guide without duplicating contradictory commands or paths.
- The guide describes only implemented issuer commands for CA initialization,
  inspection, CA-log verification, KRL reconciliation/revocation, and CA
  rotation after Epic 6 is complete.
- It documents the protected recovery set and boundaries for the SQLite demo:
  CA private/public key material, SQLite state, and the materialized KRL.
  It states that password verifiers and TOTP secrets in SQLite are sensitive.
- It gives documentation-level recovery guidance—protect backups, restore the
  related state consistently, validate with the provided commands, and confirm
  systemd readiness—without adding an automated backup or restore mechanism.
- It explains that synchronized time is an operational prerequisite for
  certificate validity, KRL cleanup, and CA-rotation overlap.
- It distinguishes project-supplied systemd/journald behavior from
  installer-owned monitoring, alerting, log retention, incident process, and
  backup infrastructure.

### US-2: Give the target-host operator a bounded offline-host guide

As a target-host operator, I can install and maintain only the public CA
material, host helper, local policy, and optional KRL needed for offline SSH
authorization, so that production hosts remain independent of the issuer and
office network during login.

**Acceptance criteria:**

- The target-host guide remains consistent with the packaged helper contract,
  OpenSSH 9 requirement, `/opt/ski-authorize` layout, `ski-authz` account, and
  sole external `sshd_config.d` fragment.
- It documents deliberate public-CA hand-off and fingerprint comparison, and
  continues to prohibit copying issuer private keys, SQLite state, dotenv
  files, identity data, agent material, or user private keys to a target host.
- After Epic 6, it documents KRL adoption as optional configuration-management
  deployment: a host may receive a materialized KRL and enable `RevokedKeys`,
  or may omit it and rely on the configured certificate lifetime. Neither mode
  contacts the issuer during login.
- It documents the 25-hour default offline group-removal window and the
  boundaries of immediate local-policy changes and optional KRL revocation.
- It states that SELinux labels/policy, host account lifecycle, firewall rules,
  configuration management, and production-host validation are owned by the
  installing organization. It must not recommend broad `audit2allow` rules or
  weakening SELinux to run the helper.
- It preserves the manual Rocky Linux 9.x UTM smoke result and clearly labels
  Debian/Ubuntu instructions as documented rather than project-tested.

### US-3: Give end users a concise certificate-and-agent guide

As an end user, I can obtain, inspect, renew, and safely use my short-lived
certificate identity, so that I understand the agent-forwarding trust boundary
and the expected 25-hour lifecycle.

**Acceptance criteria:**

- The end-user documentation gives the supported issuer-login workflow,
  password-plus-TOTP experience, agent-forwarding requirement, successful
  result, and `ssh-add -l` verification.
- It explains that the generated private key and certificate are held in the
  existing agent rather than written beneath `~/.ssh`, and that the issuer must
  be the only trusted agent-forwarding destination.
- It states certificate lifetime and renewal expectations without promising a
  client daemon, automatic renewal, or user-managed certificate files.
- It separates the issuer-login workflow from direct SSH login to a configured
  target host and explains that host authorization is local and offline.
- It names the practical failure boundaries: no forwarded agent means no
  issuance, failed password/TOTP means no new identity, and changing group
  membership affects newly issued certificates subject to the documented
  offline lifetime/KRL behavior.

### US-4: Make the project-to-installer handoff unambiguous

As an adopting organization, I can identify the exact boundary between this
proof of concept and my production responsibilities, so that I do not mistake
documentation for a promised integration or security control.

**Acceptance criteria:**

- The relevant `docs/` guides consistently say that the repository provides a
  SQLite-backed demo issuer and an offline host helper, not a production
  identity backend.
- They identify production identity adapters (LDAP, Active Directory, Okta, or
  another authority) as organization-owned implementations behind the
  documented identity interface, with organization-owned credentials,
  availability, directory semantics, and review.
- They identify configuration management, CA public-key and optional KRL
  distribution, monitoring/alerting, SELinux packaging/local policy, incident
  response, break-glass policy, and assurance drills as installer-owned work.
- They make no claim that the repository provides a host enrollment service,
  remote administration API, external network dependency for production login,
  production support commitment, or future Epic 7 implementation.
- Terminology, links, paths, commands, and claimed test coverage are reviewed
  across `docs/` so that no guide contradicts the architecture or another
  guide.

## Delivery boundary

The epic is complete when the documentation has been reviewed against the
implemented post-Epic-6 command surface and runtime behavior, all relevant
guides agree on the same trust and ownership boundaries, and no code or test
artifact outside `docs/` has changed.
