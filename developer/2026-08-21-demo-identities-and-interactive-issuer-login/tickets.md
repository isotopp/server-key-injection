# Demo identities and interactive issuer login — tickets

## Implementation rules

Implement these tickets in order. During the code-generation step, begin every
ticket with one public behavioural test, make only that test pass, and then add
the next behaviour. Do not write a ticket's complete test suite before its
implementation. Refactor only while the suite is green.

Tests exercise public command-line, store, runtime, and SSH interfaces. Use
real temporary SQLite databases, local sockets, AsyncSSH clients, subprocesses,
and isolated agents where practical. Substitute only external boundaries such
as interactive terminal input, systemd, and time; do not mock application
modules or assert private call sequences.

Run `uv run ruff format`, `uv run ruff check --fix`, `uv run ty check`, and
`uv run pytest` before completing each ticket. Commit every completed ticket
with the git-commit skill before beginning the next one.

This epic retains the process-local disposable user CA and one-hour `test-`
credential from Epic 1. It must not add persistent user-CA keys, real
certificate records, certificate group principals, KRLs, production-host
authorization, a production identity-provider adapter, or daemon lifecycle
commands.

## 1. Persistent issuer SSH host identity

**Stories.** US-1.

**Outcome.** A service has one stable Ed25519 SSH host identity for the life of
its SQLite database, rather than generating a new host key on every process
start.

**Behavioural tests, in order:**

1. Starting a runtime with a fresh temporary database creates a usable Ed25519
   host identity; a real local SSH client records its public-key fingerprint.
2. Stopping and restarting against that same database presents the same host
   key fingerprint, while a different database presents a different one.
3. A malformed, absent, or unsupported persisted host-key record causes startup
   to fail before any listener emits ready; it never silently generates a
   replacement key.
4. The host private key has no public display, journal, console, dotenv, or
   separate-file path, and remains protected by the existing SQLite permissions.

**Implementation boundary.** Add one explicit transactional SQLite migration
for a singleton `ssh_host_keys` record holding the Ed25519 private key, public
key, and fingerprint. Expose a small state-owned load-or-create host-key
operation, not SQLite rows to server code. Refactor `TracerIssuer` to receive a
loaded server host key from `ServiceRuntime`; it must stop generating one in
`start()`. The state boundary may generate the first key, but corruption is
always an error. Do not add a host-key CLI command, environment variable,
automatic rotation, or export path.

**Done when.** Real SSH handshakes demonstrate stable same-database and
different-database host identities, and malformed state proves fail-closed
startup without listener leakage.

## 2. Demo identity schema and replaceable store

**Stories.** US-2 and the identifier/cryptography decisions.

**Outcome.** SQLite demo identity data has a narrow, replaceable
`IdentityStore` contract with strict canonical identifiers and no CA-related
state.

**Behavioural tests, in order:**

1. Migrating a database already containing its issuer host identity creates
   only `users`, `groups`, and `user_groups`, preserving the host key and all
   earlier foundational state.
2. The public SQLite store accepts only canonical usernames matching
   `^[a-z][a-z0-9_-]{0,31}$` and group names matching
   `^[a-z][a-z0-9-]{0,62}$`; uppercase, Unicode, overlong, duplicate, and
   malformed values fail without partial rows.
3. Public group lookup returns one stable canonical snapshot and reports
   missing, disabled, malformed, or unavailable identity data as a failure,
   never as a usable empty authenticated identity.
4. A runtime or authentication-facing fixture can substitute another
   `IdentityStore` implementation without SQLite-specific calls.

**Implementation boundary.** Add direct, locked `argon2-cffi` and `PyOTP`
dependencies and update `uv.lock`. Define a deep `IdentityStore` interface and
`SqliteIdentityStore`; keep SQLite schema/version migration and identifier
validation behind that boundary. Store users, Argon2id verifier text, TOTP
secret, enabled status, groups, and memberships only. Do not use the identity
store from the SSH server yet, prompt for secrets, or add public commands in
this ticket.

**Done when.** Migration, identifier, snapshot, failure, and replacement-store
tests pass through public state/store interfaces, and the dependency lockfile
is current without introducing any CA/certificate/KRL tables.

## 3. User enrollment and redacted read-only commands

**Stories.** US-3 and US-8.

**Outcome.** An operator can enroll one canonical demo user through the public
CLI and inspect only redacted identity state.

**Behavioural tests, in order:**

1. `ski user add USERNAME` prompts through a substituted terminal-secret
   boundary, creates an enabled user with an Argon2id verifier, and returns one
   enrollment result containing an `otpauth://` URI and its Base32 secret.
2. The command parser has no password, TOTP-secret, database, or config-file
   argument; captured regular output, structured events, and errors contain
   neither supplied secret nor password verifier.
3. `ski user show USERNAME` returns canonical name, enabled state, and current
   groups only; `ski user list` returns user names and enabled state only.
4. Duplicate, malformed, or persistence-failed enrollment leaves no partial
   user or secret; one successful mutation commits before notifying an injected
   local service-manager boundary, while a stopped service remains success.
5. `--help` for every introduced user command works without opening SQLite;
   `ski --version` remains unchanged.

**Implementation boundary.** Extend the existing CLI hierarchy with `user`
subcommands and a small terminal/prompt boundary suitable for real concealed
input and deterministic tests. Generate at least 160-bit TOTP entropy with
`secrets`, construct enrollment material with PyOTP, and present it once from
the successful command path. Reuse the existing post-mutation notifier only
after the SQLite transaction commits. Do not render QR codes, accept secrets in
arguments/environment, or add user deletion.

**Done when.** CLI-level tests prove enrollment, redaction, help, failure
atomicity, and commit-before-notification ordering with no secret logged or
persisted outside SQLite.

## 4. Account status and credential replacement commands

**Stories.** US-4 and US-8.

**Outcome.** Operators can change demo account eligibility and credentials
without displaying, partially replacing, or retaining credential material.

**Behavioural tests, in order:**

1. `ski user enable USERNAME` and `ski user disable USERNAME` change only the
   enabled state and preserve groups and credentials.
2. `ski user password set USERNAME` accepts replacement secret input only via
   the terminal boundary, stores a new Argon2id `PasswordHasher` verifier, and
   does not expose the password or encoded verifier.
3. `ski user totp regenerate USERNAME` atomically replaces the secret, returns
   the new URI/Base32 value once, and makes the prior TOTP value fail
   verification immediately.
4. A failed password or TOTP replacement leaves the prior working credential
   intact; no malformed or partial replacement is observable.
5. Each successful mutation commits before one service notification, while
   failed notification reports a retryable non-success without rolling back or
   repeating the mutation.
6. A successful password authentication detects outdated encoded Argon2
   parameters and rehashes only after verification; test parameter selection is
   injected so tests never depend on production benchmark timing.

**Implementation boundary.** Centralize password hashing, verification,
rehash policy, and TOTP enrollment/verification behind small identity-service
operations. Benchmark and select production defaults separately from tests;
encode them as application defaults rather than dotenv settings. Reuse the
terminal and notifier boundaries from Ticket 3. Do not implement account
deletion, persistent lockout, or application-managed rate limiting.

**Done when.** Public CLI/store tests demonstrate safe status and credential
lifecycle behavior, including replacement atomicity and post-commit notification
semantics.

## 5. Group and membership command family

**Stories.** US-5 and US-8.

**Outcome.** Operators can maintain canonical demo groups and memberships,
which provide a stable issuer-side snapshot for a later authenticated request.

**Behavioural tests, in order:**

1. `ski group add GROUP`, `ski group show GROUP`, and `ski group list` create
   and display canonical group data without credentials or enrollment secrets.
2. `ski group member add GROUP USERNAME` and `ski group member remove GROUP
   USERNAME` change one membership atomically and reject unknown, duplicate, or
   absent inputs without changing state.
3. `ski group remove GROUP` rejects a non-empty group and removes an empty one.
4. `ski user show` and group lookup reflect committed membership changes, but a
   previously obtained store snapshot remains unchanged.
5. Each mutating group command notifies only after commit; `show` and `list`
   commands have no notification path.

**Implementation boundary.** Add the documented `group` CLI hierarchy using
the store, terminal, and notifier boundaries already established. Keep groups
stored without the `group:` prefix. Do not add group claims to the dummy
certificate, a group deletion cascade, or any production-host policy logic.

**Done when.** CLI-level tests cover the complete documented group command
surface, membership integrity, snapshots, redaction, and durable mutation
ordering.

## 6. Keyboard-interactive multi-factor issuer authentication

**Stories.** US-6 and US-9.

**Outcome.** The issuer SSH server authenticates one canonical enabled demo
user through password and TOTP before admitting the request session.

**Behavioural tests, in order:**

1. A real AsyncSSH client connecting as an enabled enrolled user receives
   distinct `Password:` and `2FA:` keyboard-interactive prompts and is admitted
   only when both factors verify.
2. An unknown user, disabled user, bad password, bad TOTP code, malformed
   input, and store error all receive one indistinguishable authentication
   denial and cannot start a session or agent operation.
3. Each connection receives at most one password/TOTP exchange; retrying after
   denial requires a new SSH connection.
4. Verification uses PyOTP 30-second time steps with `valid_window=1` through
   an injected clock, proving previous/current/next acceptance and values
   outside that window fail deterministically.
5. The server uses only the injected `IdentityStore` contract, and logging or
   client output contains no password, TOTP value/secret, verifier, or raw
   store error.

**Implementation boundary.** Replace the tracer's unauthenticated
`begin_auth()` behavior with AsyncSSH keyboard-interactive authentication,
carrying only the canonical authenticated identity and its stable group snapshot
into the later session. Keep connection rate limiting external and add neither
per-account lockout nor a second authentication protocol. Do not inject a
credential in this ticket; admission alone is the tracer bullet.

**Done when.** Real local SSH tests prove multi-factor admission and uniform
fail-closed denials, with a controllable clock and no secret-bearing log or
response path.

## 7. Authenticated disposable credential injection

**Stories.** US-7 and US-9.

**Outcome.** An authenticated, forwarded-agent request receives the existing
harmless disposable credential together with its current normalized group
summary.

**Behavioural tests, in order:**

1. A complete real keyboard-interactive and forwarded-agent connection for an
   enrolled user injects one fresh one-hour `test-` identity and reports the
   authenticated group snapshot before closing.
2. A successful authentication without agent forwarding reports the forwarding
   failure and adds no identity.
3. A store/group lookup failure after factor verification ends the request
   without injection and without a partial group message.
4. A restart retains the SSH host identity but creates a different disposable
   user CA, preserving Epic 1's tracer boundary.
5. The completion and operational events contain only the permitted identity,
   decision, request, and group-summary data; they contain no credentials,
   generated private key, agent payload, or complete environment.

**Implementation boundary.** Bind the immutable authenticated identity/group
snapshot to the request scope before contacting the forwarded agent. Adapt the
existing tracer injector and session success message; preserve its disposable
CA, one-hour lifetime, and `test-` key identifier. Do not issue a persistent
certificate, include group principals in the dummy certificate, or persist an
issuance record.

**Done when.** An end-to-end local SSH-agent test proves the documented login
experience and verifies all failed paths leave the agent untouched.

## 8. Epic security and operational regression

**Stories.** US-8, US-9, and all Epic 3 scope exclusions.

**Outcome.** The complete demo identity service is testable and supportable
without quietly acquiring production issuance or authorization capability.

**Behavioural tests and verification, in order:**

1. Full CLI help tests enumerate precisely the service and documented user/group
   commands; no CA/KRL command, user deletion, daemon lifecycle command,
   database/config override, QR command, or host-key administration command
   appears.
2. Regression tests inspect public database schema information and demonstrate
   that only the foundational, SSH host-key, and demo identity tables were
   added; no CA/certificate/revocation/KRL/host-authorizer tables exist.
3. Redaction tests cover command output, console events, journald adapter
   fields, authentication denials, and injection failures with synthetic
   passwords, verifiers, TOTP values/secrets, host private key data, and agent
   payload markers.
4. Documentation verification keeps `docs/dotenv.example` accurate: host-key
   material is database-backed and no host-key environment variable is offered.
5. Run the full formatter, linter, type checker, and test suite, including the
   existing service shutdown/reload and systemd-unit tests.

**Implementation boundary.** Add only regression tests and narrowly required
documentation updates discovered by the preceding tickets. Do not enlarge the
public protocol, create a production access credential, or add controls that
were explicitly assigned to external deployment infrastructure.

**Done when.** The standard project checks pass and the test suite gives clear
evidence that Epic 3's authentication and host identity are security-bounded
while the injected certificate remains intentionally useless outside the demo.
