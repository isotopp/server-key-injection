# Security review

## Scope and deployment assumptions

This is a repository-wide review of the current Python SSH certificate issuer,
its CLI, SQLite state, AsyncSSH listener, agent-injection path, and systemd
deployment example at revision `afdb488d207813e12b20d17d0865378b51a32212`.
It records findings and recommendations only; it does not create implementation
tickets.

The reviewed deployment is a dedicated issuer machine in the corporate office
network. Office clients reach it directly, and then reach production through a
firewall; production cannot initiate connections into the office. External
access is limited to the existing VPN and endpoint-security controls. The
SQLite user, password-verifier, TOTP, and group store is strictly a local demo
for virtual production hosts, not a production identity source. A production
identity provider will implement the existing narrow interfaces against LDAP,
Active Directory, or Okta.

The install account owns a non-symlinked, mode-0700 home and all issuer files.
The daemon runs as that account under the host's system systemd. These are
security requirements, not merely installation preferences.

## Review method and coverage

The review combines the repository threat model in
[`ski-threat-model.md`](ski-threat-model.md), Python security best-practices,
source-to-sink review, deployment review, and a Codex Security standard scan.
The scan covered these security surfaces:

1. SSH listener, keyboard-interactive authentication, and SSH channel policy.
2. Certificate construction, CA loading, and forwarded-agent injection.
3. SQLite state, host-key handling, password verification, TOTP, and groups.
4. CLI administration, CA lifecycle commands, and systemd notification.
5. Runtime configuration, dotenv precedence, logging, and signal handling.
6. Systemd unit and operator documentation.
7. Existing integration and deployment tests.

The scanner ran in sequential degraded mode: this session did not have the
independent-worker capacity required for its normal baseline auditor and
parallel investigations. Findings were therefore independently traced here,
not corroborated by separate workers. Targeted existing tests passed: `14`
authentication/listener tests, plus `18` configuration/systemd tests; one
systemd syntax test was skipped because `systemd-analyze` is unavailable on the
review host.

## Findings

### SR-1 — Unbounded pre-authentication work enables office-network denial of service

**Severity:** high (availability)
**Confidence:** high

`ski serve` binds both wildcard addresses by default
([`src/ski/cli.py:61`](../../src/ski/cli.py:61),
[`src/ski/server.py:225`](../../src/ski/server.py:225)). Each new connection
can start the password-and-TOTP exchange
([`src/ski/server.py:97`](../../src/ski/server.py:97)). A supplied password
for an existing user reaches Argon2 verification
([`src/ski/identities.py:365`](../../src/ski/identities.py:365)); no connection,
per-source, per-account, or global admission limit is present around the
listener or the exchange.

An authenticated corporate-network device, compromised VPN endpoint, or an
otherwise permitted office client can open concurrent SSH connections and
submit keyboard-interactive responses. This consumes connection state and
expensive password-verification work before authentication succeeds, reducing
or preventing legitimate daily certificate renewal. Office network controls
reduce exposure from the Internet, but do not defend the service against an
in-scope compromised endpoint.

The issuer correctly permits only one exchange per connection and aborts failed
exchanges ([`src/ski/server.py:106`](../../src/ski/server.py:106),
[`src/ski/server.py:128`](../../src/ski/server.py:128)). Those controls do
not bound reconnection or concurrent connections.

**Decision — accepted risk.** Do not add issuer-side rate or failure limiting for
this deployment. The corporate environment can identify the source of this
attack, respond to it outside this service, and already provides compensating
controls in other services. Revisit the decision if the issuer's network
exposure or incident-response capability changes.

### SR-2 — Mandatory secret-file invariants are documented but not enforced by the application

**Severity:** medium
**Confidence:** high

The state database contains the issuer SSH host private key
([`src/ski/migrations.py:23`](../../src/ski/migrations.py:23)) as well as demo
password verifiers and TOTP secrets
([`src/ski/migrations.py:32`](../../src/ski/migrations.py:32)). The CA private
key is read from the configured path
([`src/ski/ca.py:45`](../../src/ski/ca.py:45)). At configuration load, those
paths are checked only for a usable writable parent directory
([`src/ski/configuration.py:58`](../../src/ski/configuration.py:58),
[`src/ski/configuration.py:72`](../../src/ski/configuration.py:72)). Opening
the database adjusts the leaf database and lock-file mode to `0600`
([`src/ski/state.py:225`](../../src/ski/state.py:225)), but does not reject an
unsafe owner, ancestor permission, or symlink in the configured state or CA
path.

The provided unit and installation guide establish a strong deployment pattern:
dedicated `ski` ownership, mode-0700 directories, `ProtectSystem=strict`, and
restricted read/write paths
([`docs/systemd/ski.service:8`](../../docs/systemd/ski.service:8)). Under the
stated assumptions that pattern prevents the prerequisite. The application
nevertheless accepts a weakened hand-built deployment and may then load or
create secrets in a location readable or replaceable by another local account.
That could disclose the host key, TOTP secrets, or CA private key, or replace
issuer state.

**Decision — bounded mitigation.** Before opening issuer state or CA material,
require each target to be a regular file and reject symlinks. Require the
expected owner and group, and reject group- or world-writable files. The
dedicated mode-0700 home and systemd hardening remain required deployment
controls; this mitigation deliberately does not add broader ancestor-path
validation.

### SR-3 — Authentication timing distinguishes unknown users from wrong passwords

**Severity:** low
**Confidence:** medium

For an unknown but canonical username, `get_user()` raises and
`verify_password()` returns `False` without running Argon2
([`src/ski/identities.py:280`](../../src/ski/identities.py:280),
[`src/ski/identities.py:365`](../../src/ski/identities.py:365)). For a known
enabled user, it performs Argon2 verification before returning the same false
result ([`src/ski/identities.py:370`](../../src/ski/identities.py:370)). The
server aborts either failed exchange ([`src/ski/server.py:151`](../../src/ski/server.py:151)),
but it does not normalize the different computation time.

An office-network attacker can make repeated failed attempts and statistically
distinguish valid account names from invalid ones. The exact signal has not been
benchmarked over the target network, hence medium confidence. This does not
authenticate an attacker, and canonical user names may already be known to
operators, which keeps the severity low. It nevertheless helps targeted
credential attacks.

**Decision — bounded mitigation.** Verify an Argon2 dummy hash when lookup
fails or the account is disabled. The accepted SR-1 decision means no
rate/failure policy is added here. Do not add timing-regression tests: they
would slow the suite and be dependent on timing rather than the desired
behavioural contract.

## Confirmed controls and intentionally deferred work

- The issuer has no arbitrary command-execution surface, and direct TCP
  forwarding is rejected by integration tests
  ([`tests/test_server.py:126`](../../tests/test_server.py:126)).
- Issuance is gated on password plus TOTP and a current post-authentication
  group snapshot; missing forwarding or identity-store failures do not inject a
  credential ([`src/ski/server.py:140`](../../src/ski/server.py:140),
  [`tests/test_authenticated_injection.py:400`](../../tests/test_authenticated_injection.py:400)).
- Certificate issuance uses a fresh Ed25519 user key, a random 64-bit serial,
  canonical principals, a fixed 25-hour validity interval, and an explicit
  extension allow-list ([`src/ski/credentials.py:82`](../../src/ski/credentials.py:82)).
- The agent workflow removes only credentials that it can bind to the active CA,
  identity, serial, principal structure, and marker
  ([`src/ski/injection.py:90`](../../src/ski/injection.py:90)); unrelated
  agent identities are preserved by integration tests.
- The current empty KRL, absent production-host trust helper, offline group
  authorization, CA rotation, and production identity adapter are intentionally
  deferred architecture work. They are not presented as implementation defects
  in this review because the docs explicitly label the current issuer as a
  demo and no production host trusts its certificates.

## Suggestions

- Add a repository `SECURITY.md` before the first deployment beyond the demo.
  It should make the corporate-network assumption, dedicated-account filesystem
  contract, incident contact, supported version, and non-production limitations
  visible without requiring operators to infer them from several documents.
- Re-run this review after the host-authorization, KRL, and external identity
  provider epics. Those features create new cross-host and identity-provider
  trust boundaries that the present source cannot validate.
