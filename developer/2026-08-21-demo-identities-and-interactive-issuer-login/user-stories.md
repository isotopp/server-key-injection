# Demo identities and interactive issuer login

## Epic outcome

Replace the anonymous dummy requester with a demo identity system backed by the
issuer's existing SQLite database. An enabled demo user connects to the issuer
with agent forwarding, authenticates with a password and TOTP code, and learns
which current groups the issuer accepted for that login.

This remains a deliberately non-production issuance path. A successful login
continues to inject only the existing disposable, one-hour `test-` credential.
Persistent CA keys, 25-hour certificates, signed group principals, and
production-host acceptance remain the responsibility of later epics.

## Scope and boundaries

This epic implements only [Epic 3 — Demo identities and interactive issuer
login](../architecture.md#epic-3--demo-identities-and-interactive-issuer-login)
and the [demo identity store](../architecture.md#demo-identity-store).

It adds a persistent Ed25519 issuer SSH host identity, the `IdentityStore`
abstraction, a SQLite implementation, demo password/TOTP authentication, group
membership administration, and the documented `ski user` and `ski group`
commands. It also changes the issuer SSH interaction from the current anonymous
tracer request to a password-plus-TOTP-authenticated request.

It does not create persistent CA keys or CA/certificate/audit tables, sign
production-useful certificates, add group claims to a certificate, implement a
KRL, expose the database to production hosts, or add a production identity
provider. It does not add service-account switching, emergency access,
temporary access, user deletion, or any public daemon lifecycle command.

## CLI surface in this epic

The forms below omit the usual `uv run` prefix. Every command continues to
support `--help`, and `ski --version` remains available without opening the
database. Commands resolve `SKI_CA_DATABASE` through the existing environment
search order; this epic adds no `--config` or `--database` override.

| Command                                                                          | Options                             | Epic 3 responsibility                                                                                  |
|----------------------------------------------------------------------------------|-------------------------------------|--------------------------------------------------------------------------------------------------------|
| `ski serve`                                                                      | Existing `--bind IP`, `--port PORT` | Load the persistent issuer host key and replace its anonymous tracer interaction with the password-plus-TOTP flow. |
| `ski user add USERNAME`                                                          | none                                | Prompt for the initial password and enroll TOTP.                                                       |
| `ski user show USERNAME` / `ski user list`                                       | none                                | Display redacted account and membership state.                                                         |
| `ski user enable USERNAME` / `ski user disable USERNAME`                         | none                                | Change issuance eligibility without deleting history.                                                  |
| `ski user password set USERNAME`                                                 | none                                | Prompt for and replace the password verifier.                                                          |
| `ski user totp regenerate USERNAME`                                              | none                                | Replace the TOTP secret and show enrollment data once.                                                 |
| `ski group add GROUP` / `ski group remove GROUP`                                 | none                                | Create a group or remove an empty group.                                                               |
| `ski group show GROUP` / `ski group list`                                        | none                                | Display group membership or list groups.                                                               |
| `ski group member add GROUP USERNAME` / `ski group member remove GROUP USERNAME` | none                                | Change one membership.                                                                                 |

The CA/KRL command family in the architecture (`ski ca init`, rotation,
revocation, reconciliation, and CA-log commands) belongs to later epics and is
not scaffolded as empty commands here. There remains no `ski stop`, `ski
reload`, `ski status`, `--daemonize`, `--pid-file`, or log-file option:
systemd owns service lifecycle and logging.

## User stories

### US-1: Establish a persistent issuer SSH host identity

As an SSH client user, I can verify the same Ed25519 host identity after an
issuer restart, so that password and TOTP prompts are bound to the intended
issuer rather than an ephemeral or substituted server.

**Acceptance criteria:**

- The SQLite database contains one persistent Ed25519 SSH host private key and
  its corresponding public key/fingerprint, distinct from every future user CA
  key.
- First-time identity setup generates the host key with a cryptographically
  secure RNG and persists it transactionally; every later `ski serve` instance
  using that database loads the same host identity.
- A server using a different database presents a different host identity. A
  malformed, missing, or unsupported stored host key prevents listener startup
  and does not cause a replacement key to be generated silently.
- The host private key is never logged, displayed by a `ski` command, copied to
  a separate key file, or included in a test fixture. Existing database file
  protection applies to it.
- Public-key distribution, client `known_hosts` management, database backup,
  and host-key rotation are external operational responsibilities. This epic
  adds no host-key CLI command or automatic rotation mechanism.

### US-2: Isolate demo identities behind a replaceable store

As an issuer developer, I can use an `IdentityStore` interface rather than
SQLite-specific calls in SSH handling, so that a future production identity
provider can replace the demo implementation without changing the issuer
authentication contract.

**Acceptance criteria:**

- `IdentityStore` has explicit operations for creating and inspecting users,
  changing account status and credentials, verifying a password and TOTP
  factor, looking up current groups, and administering groups and memberships.
- The SSH issuer depends on only that interface for identity, authentication,
  enabled status, and group lookup; it neither queries SQLite directly nor
  reads identity configuration from the environment while handling a request.
- `SqliteIdentityStore` stores the demo data in the database selected by
  `SKI_CA_DATABASE`, using explicit, versioned, transactional schema changes
  that preserve the Epic 2 foundational state.
- Apart from the issuer host-key record, the schema contains only the identity
  data needed here: canonical users, password verifiers, TOTP secrets, enabled
  status, groups, and user/group memberships. It introduces no CA,
  certificate, revocation, KRL, or production-host authorization records.
- Store failures, malformed state, missing users, disabled users, and failed
  group lookups fail closed. The SSH-facing path does not treat an error as an
  authenticated user with an empty group set.
- Tests exercise the public store interface with a temporary real SQLite
  database and can substitute a non-SQLite store at the issuer boundary.

### US-3: Create and inspect demo users safely

As a local operator, I can create a demo user and inspect redacted account
state, so that a person can be enrolled before attempting issuer login.

**Acceptance criteria:**

- `ski user add USERNAME` accepts only an already-canonical lowercase ASCII
  name matching `^[a-z][a-z0-9_-]{0,31}$`, creates one enabled user, prompts
  for the initial password without accepting it as a command-line argument,
  and initiates TOTP enrollment.
- Initial enrollment generates at least 160 bits of secret entropy through
  Python's `secrets` module and presents both the `otpauth://` URI and its
  Base32 secret exactly once to the invoking terminal. It does not render a QR
  code and does not write enrollment information to logs, shell history,
  normal command output after the enrollment step, or any repository artifact.
- `ski user show USERNAME` displays only the canonical user name, enabled
  status, and current group memberships; it never displays a password verifier,
  TOTP secret, or provisioning value.
- `ski user list` displays canonical users and enabled/disabled state without
  credential material or group-secret data.
- Duplicate, malformed, or unavailable user input fails without a partial user
  or membership record. User-facing errors are concise and do not disclose a
  password or TOTP value.
- No `ski user delete` command is added. Disabling later preserves the identity
  and its future audit history.

### US-4: Maintain demo account status and credentials

As a local operator, I can disable an account, replace its password verifier,
or regenerate its TOTP enrollment, so that the demo issuer can model common
identity lifecycle changes without retaining old secrets.

**Acceptance criteria:**

- `ski user enable USERNAME` and `ski user disable USERNAME` change only the
  account's issuance eligibility and retain the user and membership records.
- `ski user password set USERNAME` prompts for a replacement password and
  stores only an Argon2id verifier through `argon2-cffi`'s
  `argon2.PasswordHasher`. Neither the supplied password nor the verifier is
  printed or logged.
- `ski user totp regenerate USERNAME` atomically replaces the prior TOTP
  secret, generated with `secrets`, and presents the new PyOTP
  `otpauth://` URI and Base32 secret once; the old secret stops authenticating
  immediately after the successful transaction.
- Password replacement and TOTP regeneration never accept secret material as
  a command-line option, environment value, or positional argument.
- Failed validation or persistence leaves the former password verifier and
  TOTP secret usable; a partially updated credential pair is never visible.
- Password-hash defaults are benchmarked on issuer hardware before release and
  locked into the application configuration. A successful password
  authentication rehashes the verifier when `PasswordHasher` reports that its
  stored parameters are obsolete.

### US-5: Manage groups and memberships locally

As a local operator, I can maintain demo groups and memberships, so that each
authenticated issuer login has a current, well-defined group snapshot.

**Acceptance criteria:**

- `ski group add GROUP`, `ski group show GROUP`, and `ski group list` accept
  only already-canonical lowercase ASCII group names matching
  `^[a-z][a-z0-9-]{0,62}$`, and create and inspect them without exposing user
  credential data.
- `ski group member add GROUP USERNAME` and `ski group member remove GROUP
  USERNAME` make one membership change atomically and reject unknown users,
  unknown groups, and duplicate or absent memberships without changing state.
- `ski group remove GROUP` succeeds only when the group has no memberships;
  otherwise it fails with a clear non-sensitive error and leaves the group
  intact.
- Group lookup returns a stable, validated snapshot for one authentication
  attempt. Concurrent later membership changes do not mutate the snapshot
  already bound to that attempt.
- This epic reports groups to the authenticated user but does not yet include
  any group in a non-disposable certificate or make them usable by a production
  host.

### US-6: Authenticate issuer SSH logins with password and TOTP

As an enabled demo user, I can connect with `ssh ssh.example.com -A -l
username`, answer password and TOTP prompts, and authenticate as the canonical
account, so that the issuer does not trust a user name supplied by the client
alone.

**Acceptance criteria:**

- The issuer uses an SSH keyboard-interactive exchange with distinct password
  and `2FA` prompts. Each SSH connection receives at most one exchange, and
  the normal flow is compatible with `ssh -A -l username`.
- The requested SSH login name is validated and resolved through
  `IdentityStore`; successful password and TOTP verification bind the request
  to that canonical enabled identity.
- A nonexistent user, disabled account, invalid password, invalid TOTP value,
  malformed input, or store error is denied without injecting an identity.
- Denial responses do not distinguish authentication-failure causes to the
  remote requester and do not disclose password, TOTP, verifier, secret, or
  detailed directory/store state in logs.
- Password and TOTP input exist only for verification. They are never added to
  an event, exception message, SQLite audit-like record, SSH response, or test
  fixture.
- TOTP verification uses PyOTP's 30-second steps and accepts only the preceding,
  current, and following step (`valid_window=1`). Authentication tests use a
  controllable clock/TOTP source and exercise real SSH keyboard-interactive
  exchanges as well as direct store behaviour.
- SSH connection rate limiting is an external deployment responsibility. The
  application does not implement source-address throttling or persistent
  per-account lockout in this demo.

### US-7: Complete the authenticated demo issuer interaction

As an authenticated demo user with a forwarded agent, I receive the harmless
tracer identity and a summary of my current groups, so that the interactive
experience proves authentication, group lookup, and agent injection together.

**Acceptance criteria:**

- After both factors succeed, the issuer obtains one group snapshot from
  `IdentityStore`, requires the forwarded agent channel, and performs the
  existing disposable credential injection flow.
- The completion message states that a key was loaded, gives the current
  tracer validity, lists the normalized group names used for the request, asks
  the user to run `ssh-add -l`, and then closes the session.
- A failed or absent agent-forwarding channel after successful authentication
  does not add an identity and does not reveal credential or agent payload
  data.
- A group lookup failure after factor verification is a denial; it cannot
  produce a successful injection with missing or partial group information.
- The injected credential remains a fresh, one-hour, process-local-CA
  `test-` identity. It is not a 25-hour certificate and is not accepted by any
  production host.

### US-8: Make identity changes durable before daemon notification

As an operator, I can run the local identity commands while the issuer is
running or stopped, so that durable changes are never coupled unsafely to a
daemon reload attempt.

**Acceptance criteria:**

- Every successful mutating `ski user` or `ski group` command commits its
  SQLite transaction before calling the existing local systemd reload
  notification boundary.
- A stopped `ski.service` makes notification a successful no-op; the next
  issuer start reads the committed identity data.
- A failed active-service notification does not roll back, repeat, or conceal
  the committed mutation. The command returns a clear retryable operational
  non-success result without disclosing sensitive state.
- Read-only `show` and `list` commands do not notify the daemon.
- The CLI preserves the established absence of `ski stop`, `ski reload`,
  `ski status`, `--config`, and `--database` commands.

### US-9: Keep demo credentials and operations security-bounded

As a security reviewer, I can verify that demo identity support does not turn
the tracer into a production access-control system or expose authentication
secrets.

**Acceptance criteria:**

- Passwords are stored only as calibrated Argon2id verifiers; TOTP secrets and
  the issuer SSH host private key remain sensitive SQLite data protected by the
  existing local-state file permissions.
- Journal events and console fallback output contain only stable operational
  decisions and correlation data. They exclude passwords, TOTP values/secrets,
  password verifiers, agent protocol payloads, generated private keys, and
  complete environment values.
- Authentication failures do not add an agent identity, create CA/certificate
  data, or change user/group state.
- Apart from the issuer SSH host key and demo identity data, the database has
  no persistent CA key, real certificate, revocation, KRL, or production-host
  authorization schema.
- No production identity-provider adapter, host-side helper, host policy, or
  certificate group claim is introduced in this epic.

## Decisions made during story refinement

- Administrative access remains an operating-system and database-file access
  concern. This epic adds no second in-application administrator authorization
  layer.
- Identity commands use `SKI_CA_DATABASE` through the established environment
  search contract; they add no database or configuration-file option.
- The SQLite demo is intentionally issuer-side only. Production hosts remain
  offline from the issuer and never receive the identity database.
- A current group snapshot is used only to report the successful demo login in
  this epic. Group-principal normalization and certificate claims belong to
  persistent certificate issuance.
- Password verification uses the direct `argon2-cffi` dependency and the
  high-level Argon2id `PasswordHasher`; its issuer-hardware-benchmarked
  parameters are application defaults, not operator-supplied environment
  values.
- TOTP uses the direct `PyOTP` dependency with 160-bit `secrets`-generated
  values, 30-second steps, and `valid_window=1`. Enrollment displays only an
  `otpauth://` URI and Base32 secret once; terminal QR rendering is out of
  scope.
- Canonical usernames match `^[a-z][a-z0-9_-]{0,31}$`; canonical groups match
  `^[a-z][a-z0-9-]{0,62}$`. Inputs are rejected rather than case-folded, groups
  are stored without a prefix, and a later group principal is
  `group:<group-name>`.
- The daemon permits one password/TOTP exchange per connection. Connection rate
  limiting is external to `ski`, and the demo does not implement persistent
  per-account lockout.
- The issuer SSH server has one persistent Ed25519 host key in SQLite. Client
  trust distribution, backup, and rotation are managed outside `ski`; no host
  key file-path setting or host-key CLI command is introduced.
- Existing daemon socket ownership, `Type=simple` service lifecycle, and native
  journald field conventions remain unchanged.
