# Persistent CA and ordinary certificate issuance — tickets

## Implementation rules

Implement these tickets in order. During the Code-generation step, begin every
ticket with one public behavioural test, make only that test pass, then add the
next behaviour. Do not write a ticket's whole test suite before its first
implementation slice. Refactor only while the suite is green.

Tests exercise public CLI, configuration, state, runtime, SSH, and local-agent
interfaces. Use temporary real SQLite databases, restricted temporary
directories, local Unix sockets, real AsyncSSH clients, real isolated
`ssh-agent` processes, and real OpenSSH inspection tools where practical.
Substitute only external boundaries such as time, terminal input, systemd, and
the OpenSSH KRL executable. Do not mock application modules or assert private
call sequences.

Run `uv run ruff format`, `uv run ruff check --fix`, `uv run ty check`, and
`uv run pytest` before completing each ticket. Commit every completed ticket
using the git-commit skill before beginning the next one.

This epic replaces the process-local user CA and disposable one-hour `test-`
certificate. It does not add production-host authorization, KRL revocation or
reconciliation, CA rotation, a production identity provider, or non-ordinary
access variants.

## 1. Ordinary CA configuration and extension policy

**Stories.** US-1, US-2, and US-4.

**Outcome.** The issuer has one explicit, immutable ordinary-issuance
configuration contract before any CA key, database, listener, or agent action
can occur.

**Behavioural tests, in order:**

1. A complete temporary dotenv/environment configuration yields the configured
   CA private-key path, public-key path, database path, KRL path, exactly
   25-hour ordinary certificate lifetime, and a parsed extension policy.
2. The extension parser accepts a comma-separated canonical allowlist of
   `pty`, `agent-forwarding`, `port-forwarding`, `x11-forwarding`, and
   `user-rc`; it maps each value to the corresponding OpenSSH certificate
   extension and allows port forwarding only when `port-forwarding` is listed.
3. Missing, empty, malformed, duplicate, or unsupported extension values, and
   missing/unsafe CA or KRL paths, fail configuration without opening SQLite,
   generating a key, starting a listener, or exposing the environment value.
4. A malformed or missing CA configuration makes the foreground runtime fail
   before its ready event and never fall back to the existing tracer CA.

**Implementation boundary.** Extend the immutable runtime configuration with
the CA file paths and an ordinary-certificate extension-policy value object.
The lifetime is an application constant of 25 hours: do not accept
`SKI_CERTIFICATE_LIFETIME`, another duration syntax, or a CLI lifetime option.
Require `ORDINARY_CERT_EXTENSIONS`; document every accepted identifier and its
certificate effect in `docs/dotenv.example`. Keep opaque file contents outside
the configuration snapshot. Do not load or generate a CA key in this ticket.

**Done when.** Public configuration/runtime tests demonstrate explicit,
fail-closed ordinary-issuance configuration and a safe, documented extension
allowlist.

## 2. Persistent ordinary CA, certificate, and event state

**Stories.** US-1 and US-3.

**Outcome.** SQLite has a versioned, transaction-owned CA state boundary which
can record one active public CA, ordinary certificates, and immutable events
without retaining any CA or generated user private key.

**Behavioural tests, in order:**

1. Opening an existing Epic 3 database migrates it transactionally to add only
   `ca_keys`, `certificates`, and `events`, retaining its issuer host key,
   users, groups, and memberships.
2. A public CA-state interface registers one active Ed25519 CA record containing
   its public key, fingerprint, configured private-key path, activation time,
   and status, and refuses a second active record or malformed/mismatched
   public data.
3. A public issuance-record operation accepts a cryptographically random
   64-bit serial, canonical identity, public-key fingerprint, stable principal
   sequence, fixed 25-hour validity, request ID, and outcome; it rejects a
   duplicate serial for the same CA atomically.
4. A public event operation records initialization and successful/failed
   issuance with safe fields, returns events in stable order, and offers no
   update/delete operation. Synthetic private keys, passwords, TOTP values,
   verifiers, agent payload markers, and complete environment values never
   appear in returned state.
5. Corrupt, unavailable, or newer-schema state fails closed through the public
   boundary and does not synthesize replacement CA/certificate records.

**Implementation boundary.** Add one migration version and a deep
state-owned/repository interface; do not let the SSH server query SQLite rows.
Store certificate and event metadata, not the generated user private key or
private CA material. A CA private-key *path* is permitted as local
configuration metadata but must be redacted from normal CLI/event views. Do not
add revocation, KRL-generation, maintenance, host-policy, or identity-provider
tables.

**Done when.** Real temporary SQLite tests prove migration preservation,
single-active-CA integrity, serial collision safety, append-only audit data,
and secret-free public views.

## 3. Atomic CA initialization and public CA commands

**Stories.** US-1 and US-6.

**Outcome.** An operator can initialize exactly one Ed25519 CA using configured
paths, obtain its public key, and inspect redacted status without exposing or
overwriting private material.

**Behavioural tests, in order:**

1. `ski ca init` with fresh configured temporary paths creates an Ed25519
   private key with restrictive permissions, its matching public-key file, one
   active SQLite CA record, and an empty OpenSSH-valid KRL; `ski ca show` and
   `ski ca public-key` return only public metadata/key text.
2. Restarting the command or supplying existing CA material refuses safely and
   leaves the original files and database record unchanged.
3. A failure injected at each validation, temporary-file, KRL, database, rename,
   or service-notification boundary leaves no active partial CA state and never
   deletes or changes a pre-existing target. A recoverable startup check handles
   an interrupted fresh initialization without silently accepting a mismatch.
4. The CLI accepts no `--key-type`, database, configuration, secret, or
   private-key argument. Its help lists only the documented CA commands; all
   read-only CA commands avoid daemon notification.
5. A stopped service is a durable initialization success. A failed notification
   after durable initialization reports a retryable non-success without
   rollback, duplicate initialization, private data, or raw error details.

**Implementation boundary.** Introduce narrow CA-key-file and empty-KRL writer
boundaries. The KRL writer must create a file consumable by OpenSSH and fail
closed when its required external capability is unavailable; it does not add
revocations. Stage output in the destination directory with restrictive modes,
then use atomic replacements plus a recoverable initialization state machine so
file and SQLite results cannot be mistaken for a valid active CA unless they
match. The CLI owns no authorization model beyond existing OS/database access.
Do not implement rotation, revocation, reconciliation, or KRL distribution.

**Done when.** CLI/integration tests prove safe first initialization, public-key
distribution output, idempotent refusal, failure recovery, and no secret
disclosure.

## 4. Validated active-CA loading into the service runtime

**Stories.** US-2.

**Outcome.** A live issuer can use only the configured, database-registered
Ed25519 CA and cannot become ready with partial, mismatched, or disposable
signing state.

**Behavioural tests, in order:**

1. A runtime using the initialized CA loads its configured private key and
   presents the existing stable SSH server host key while retaining the active
   CA fingerprint across restarts.
2. A missing key file, unreadable file, malformed private/public key, wrong key
   type, public/private mismatch, fingerprint mismatch, inactive/missing
   database record, or state error prevents the listener from emitting ready.
3. Every failure path releases database ownership and any partially opened
   listener, contains no private-key bytes/path contents or complete
   environment, and never creates another CA.
4. An accepted reload keeps the active signing material until a later explicit
   CA lifecycle epic; ordinary CA file-path changes require restart and cannot
   silently change the signer.

**Implementation boundary.** Add a small validated active-CA object to the
runtime and inject it into the issuer/certificate factory. Match configured
public-key file, imported private key, and persisted public fingerprint before
listener start. Preserve the persistent SSH *host* key as an independent
identity. Do not implement CA reload, key rotation, or fallback signing.

**Done when.** Real local runtime tests prove valid startup and every
malformed/mismatch case fails closed without listener or lock leakage.

## 5. Persisted-CA certificate construction and issuance records

**Stories.** US-3, US-4, and US-7.

**Outcome.** An authenticated request can create a fresh Ed25519 user
certificate signed by the active persistent CA, with fixed validity, canonical
principals, a unique serial, and durable safe issuance evidence.

**Behavioural tests, in order:**

1. A certificate factory given a validated active CA and an immutable identity
   snapshot produces a fresh Ed25519 keypair and a user certificate whose
   signature verifies against the persisted CA public key, has a unique random
   serial, canonical username `key_id`, exactly 25-hour validity, and stable
   username-plus-`group:` principals.
2. Each documented `ORDINARY_CERT_EXTENSIONS` value changes only its matching
   OpenSSH certificate extension. Unlisted extensions are denied, and an
   unlisted `port-forwarding` extension remains disabled.
3. The issuance service commits the certificate metadata and a successful event
   before returning a success result; public state exposes serial, safe
   fingerprints, identity, principals, validity, request ID, and decision, but
   never the generated private key.
4. A serial collision retries safely without replacing prior data. Identity,
   signing, persistence, and validation failures yield a failed event and no
   successful certificate record or success result.
5. All certificate and event output remains free of private-key, password,
   TOTP, verifier, agent-payload, and complete-environment markers.

**Implementation boundary.** Replace the `DisposableCertificateFactory` with a
deep ordinary-issuance service that owns serial allocation, certificate
construction, and record/event ordering. Generate private keys only after MFA
and use the immutable authenticated snapshot already carried by the request.
Use AsyncSSH's public certificate API with its explicit extension flags. Do not
persist a private key, add a KRL entry, issue temporary/emergency credentials,
or make a host trust the certificate.

**Done when.** Public certificate/store tests verify the full ordinary
certificate content and durable-success/fail-closed ordering.

## 6. Agent-owned credential replacement and authenticated SSH issuance

**Stories.** US-4, US-5, and US-7.

**Outcome.** A real authenticated forwarded-agent session replaces only the
current user's ski-owned credential with the persisted-CA certificate and
reports safe completion data.

**Behavioural tests, in order:**

1. A real enabled user completes the existing password/TOTP prompts with an
   isolated forwarded agent and receives one certificate signed by the
   initialized persistent CA; `ssh-add -L` and public OpenSSH inspection show
   its serial, key ID, principals, 25-hour validity, and configured extension
   policy.
2. A renewal removes the prior credential that the issuer proves it owns for
   that same canonical user, adds one fresh credential, and retains an unrelated
   agent identity, another user's ski credential, a different-CA certificate,
   and malformed/unrecognized entries.
3. Missing forwarding, agent listing/cleanup failure, add failure, identity
   failure, signing failure, or persistence failure leaves unrelated identities
   untouched, adds no partial new credential, emits a generic client failure,
   and records only a safe failed outcome.
4. The client response gives safe serial/key ID, expiry, and normalized groups,
   then closes. It contains no key bytes, password, TOTP, verifier, raw agent
   data, or detailed storage error.
5. Process restart retains the issuer SSH host key and active CA, but every
   successful issuance creates a fresh user keypair and serial.

**Implementation boundary.** Replace the tracer session handler with the
ordinary issuance/agent service after the existing MFA snapshot has been
bound. Define a strict ski-owned agent-identity marker tied to canonical user,
active CA fingerprint, and certificate serial; never treat a comment alone as
ownership. List and remove only provably matching certificates/keys, then add
the matching new pair with an agent lifetime bounded by certificate expiry.
Do not modify unrelated agent entries, expose user private keys, or provide
production-host login.

**Done when.** End-to-end real SSH-agent tests demonstrate safe first issuance,
renewal cleanup, unrelated-key preservation, restart behaviour, and all failed
paths.

## 7. CA log inspection, verification, documentation, and boundary regression

**Stories.** US-6 and US-7.

**Outcome.** Operators can inspect redacted ordinary CA history and verify
issuer consistency, while regression coverage ensures the epic has not acquired
future revocation or host-authorization capability.

**Behavioural tests, in order:**

1. `ski ca log list` returns redacted initialization/issuance events in stable
   order and correctly applies strict serial, canonical-user, event-kind, and
   time-window filters with a bounded default result size.
2. `ski ca log verify` succeeds for a valid initialized/issued database and
   reports non-success without mutation for SQLite integrity failure, malformed
   CA/certificate references, duplicate serial state, fingerprint mismatch, or
   invalid event relationship.
3. CLI output, console events, journald fields, failed authentication, failed
   initialization, and failed agent issuance reject synthetic key, credential,
   TOTP, verifier, agent-payload, and environment markers.
4. `docs/dotenv.example`, `README.md`, and systemd documentation describe
   the required CA paths, fixed 25-hour ordinary lifetime, documented
   extension allowlist, Ed25519-only CA, and the fact that production-host trust
   remains Epic 5 work.
5. CLI/schema regressions prove no rotation, revoke/reconcile, KRL maintenance,
   host policy, production identity, account-switch, temporary/emergency, user
   deletion, daemon lifecycle, or database/config-override interface has been
   introduced.

**Implementation boundary.** Add only the read-only inspection/verification
interfaces and narrowly required documentation discovered by prior tickets.
Verification must not repair or mutate state. Keep the empty KRL separate from
the future revocation materialization implementation. Do not add any host-side
component.

**Done when.** Standard checks pass and the public CLI, schema, logs,
documentation, and integrations provide evidence of a bounded issuer-only
ordinary certificate service.
