# Persistent CA and ordinary certificate issuance

## Epic outcome

Replace the process-local tracer CA and one-hour `test-` credential with an
ordinary persisted SSH user-CA. An enabled demo user who completes the existing
password-and-TOTP login receives a freshly generated keypair and OpenSSH user
certificate in their forwarded agent. The certificate is bound to their
canonical identity and current normalized groups, is valid for exactly 25
hours, and has an issuer-side audit record.

The certificate is deliberately not accepted by a production host until Epic 5.

## Scope and boundaries

This implements only [Epic 4 — Persistent CA and ordinary certificate
issuance](../architecture.md#epic-4--persistent-ca-and-ordinary-certificate-issuance),
the ordinary issuance portion of the [CA and KRL commands](../architecture.md#ca-and-krl-commands),
and the issuer-side [issuance flow](../architecture.md#issuance-flow).

It adds one persistent active CA, CA-file loading, certificate serials and
records, append-only CA-log events, fixed ordinary validity, signed normalized
principals, configured ordinary certificate extensions, and safe cleanup of
application-owned agent identities.

It does not add production-host trust or authorization, KRL revocation or
maintenance, CA rotation, an external identity provider, temporary/emergency
access, account switching, user deletion, or application-owned daemon
lifecycle commands. The existing SQLite demo identities, MFA, systemd model,
and `.env` search order remain in place.

## CLI surface in this epic

All forms omit the `uv run` prefix, resolve configuration through the existing
search path, support `--help`, and add neither `--database` nor `--config`.

`ORDINARY_CERT_EXTENSIONS` is a comma-separated list of ordinary certificate
extensions, for example `pty,port-forwarding`. The dotenv example will list and
explain every supported value. The issuer accepts only that documented
allowlist, rejects malformed, duplicate, or unknown values at startup, and does
not provide a CLI override.

| Command | Options | Responsibility |
| --- | --- | --- |
| `ski serve` | Existing `--bind IP`, `--port PORT` | Load the validated persisted CA and issue an ordinary certificate after MFA. |
| `ski ca init` | none (Ed25519 only) | Create one configured CA keypair, active CA record, and empty configured KRL without overwriting state. |
| `ski ca show` | `--all` | Display redacted active CA status; `--all` returns the complete current list. |
| `ski ca public-key` | `--fingerprint FINGERPRINT` | Print the active or selected CA public key for configuration management. |
| `ski ca log list` | `--serial SERIAL`, `--user USERNAME`, `--event KIND`, `--from TIME`, `--to TIME` | Query redacted CA initialization and ordinary issuance history. |
| `ski ca log verify` | none | Verify ordinary CA, certificate, serial, event, and SQLite consistency without mutation. |

`ski ca rotate prepare`, `ski ca rotate activate`, `ski ca rotate retire`,
`ski ca revoke`, and `ski ca reconcile` remain Epic 6 work. The empty KRL from
initialization is deployment preparation only; it has no revocation semantics
in this epic.

## User stories

### US-1: Initialise and inspect one persistent signing CA

As a local issuer operator, I can initialise one configured SSH user-CA and
inspect its public identity, so that I can distribute the public key without
exposing its private signing key.

**Acceptance criteria:**

- `ski ca init` validates `SKI_CA_PRIVATE_KEY`, `SKI_CA_PUBLIC_KEY`,
  `SKI_CA_DATABASE`, and `SKI_CA_KRL` before changing state; parent directories
  must already exist and be writable by the service account.
- On fresh state, initialization generates a CA keypair with a secure RNG,
  writes restrictive private-key permissions, writes the matching public key,
  creates one active CA record, and creates an empty valid KRL at its configured
  path.
- The ordinary CA algorithm is fixed to Ed25519. This epic exposes no
  `--key-type` selection or alternate signing-algorithm compatibility path.
- It is all-or-nothing: existing key files, an active CA record, inconsistent
  partial state, unsafe targets, or unsupported material fail without
  overwriting, deleting, or silently repairing anything.
- The active record contains public key, fingerprint, configured private-key
  path, activation time, and status; SQLite never stores CA private-key bytes.
- `ski ca show` and `ski ca public-key` disclose only public data. They never
  print private-key material, complete configuration, database contents, or
  agent protocol data.
- The CA fingerprint is stable across restarts and distinct from the issuer SSH
  server host-key fingerprint. Host public-key distribution remains external.

### US-2: Load CA state fail closed at issuer start

As an SSH client user, I reach an issuer with a complete and consistent signing
CA, so that it cannot fall back to a disposable or mismatched signer.

**Acceptance criteria:**

- Before listener readiness, `ski serve` validates configured private/public
  files and checks that their derived public key and fingerprint match the
  active SQLite CA record.
- Missing, unreadable, malformed, unsupported, inactive, or mismatched CA
  material prevents readiness and issuance. The daemon neither generates a
  replacement nor falls back to the process-local tracer CA.
- Private-key data, passwords, TOTP values/secrets, and complete environment
  values never appear in SSH responses, CLI errors, events, or CA logs.
- Existing SSH host-key, identity-store, bind/port, systemd, and reload
  behaviour remains unchanged.

### US-3: Persist ordinary certificate and CA-log state

As an operator, I have durable, queryable issuance records, so that every
ordinary certificate can later be attributed and investigated without storing a
generated user private key.

**Acceptance criteria:**

- A transactional versioned migration adds only `ca_keys`, `certificates`, and
  append-only `events` records, preserving existing host-key and identity data.
- Certificate records contain a random unique serial, CA fingerprint, canonical
  identity, public-key fingerprint, normalized principals, validity interval,
  request ID, and outcome. Serial uniqueness is enforced per CA without
  overwriting on collision.
- Events record CA initialization and successful/failed issuance with safe time,
  kind, decision, and correlation data. Ordinary interfaces cannot update or
  delete prior events.
- No revocation, active-revocation, KRL-generation, maintenance, production
  authorization, or external identity-provider table is introduced.
- CA private keys, generated user private keys, passwords, TOTP material, and
  raw agent payloads are never persisted in certificate or event rows.

### US-4: Issue a canonical ordinary SSH user certificate

As an enabled authenticated demo user, I receive a certificate signed by the
persisted CA, so that my agent holds an ordinary credential with my canonical
identity and current groups rather than a `test-` tracer claim.

**Acceptance criteria:**

- Existing password-and-TOTP MFA remains the admission gate. Missing, disabled,
  malformed, or unavailable identity/group data denies before key generation or
  agent contact.
- After success, the issuer generates a fresh Ed25519 user keypair and a random
  unique serial, and signs a user certificate with the active CA.
- `key_id` is the canonical username. Principals are exactly that username plus
  stable, deduplicated `group:<group-name>` values from the immutable request
  snapshot; no display name, free-form claim, or arbitrary attribute bag is
  included.
- Validity begins at issue time and ends exactly 25 hours later. Ordinary
  issuance has no lifetime environment or CLI override; shorter or different
  validity policies belong to separately designed future access variants.
- `ORDINARY_CERT_EXTENSIONS` selects only documented ordinary extensions through
  a strict comma-separated allowlist. Malformed, duplicate, or unsupported
  values fail closed before issuance; the configured result is audit-visible.
  Ordinary port forwarding is permitted only when `port-forwarding` is listed.
  Ordinary issuance has no unreviewed critical option, temporary, emergency,
  source-address, or account-switch policy.
- Signing, persistence, or agent failure produces no false success response or
  successful certificate record and writes only a safe failed-operation event.
- The completion response identifies safe serial/key-ID, expiry, and normalized
  groups, tells the user to run `ssh-add -l`, and never prints private-key or
  authentication material.

### US-5: Replace only ski-owned agent identities safely

As a renewing user, I receive one current ordinary ski credential without
losing unrelated `ssh-agent` identities, so that renewal does not accumulate
stale entries or damage existing SSH use.

**Acceptance criteria:**

- A missing, unavailable, malformed, or failing forwarded-agent channel leaves
  the agent untouched and produces a generic non-secret failure.
- Before adding the new credential, the issuer removes only identities it can
  prove this application issued for the same canonical user, using a strict
  application identifier and CA/certificate relationship—not a free-form
  comment alone.
- It retains unrelated keys, certificates from another CA, other ski users'
  identities, and malformed or unrecognizable entries.
- It adds the new private key and matching certificate as one usable agent
  credential with a lifetime no later than certificate expiry. The private key
  exists only in issuer memory and necessary agent protocol messages.
- Cleanup/addition failures do not claim success, reveal agent data, or delete
  further identities. The CA log records the safe outcome.
- Isolated real-agent tests prove renewal replaces an owned credential while
  retaining an unrelated one.

### US-6: Inspect and verify ordinary CA operations safely

As an operator or incident responder, I can inspect and verify normal CA state
and issuance history, so that I can diagnose the issuer without direct SQLite
access or secret disclosure.

**Acceptance criteria:**

- `ski ca log list` validates documented serial, canonical-user, event-kind,
  and time-window filters, uses a bounded default result size, and returns only
  redacted fields.
- `ski ca log verify` checks SQLite integrity and active-CA, fingerprint,
  serial, certificate-reference, and append-only-event consistency without
  changing state; malformed or inconsistent state returns non-success.
- Read-only CA commands never notify the daemon. `ski ca init` commits database
  state and atomically replaces files it owns before the existing reload
  notification; a stopped service is success and a post-commit notification
  failure is retryable without rollback or repetition.
- All outputs and event sinks exclude private keys, generated user keys,
  passwords, TOTP values/secrets, verifiers, full environment data, and raw
  agent payloads.

### US-7: Preserve the ordinary-issuance security boundary

As a security reviewer, I can verify that Epic 4 creates only bounded ordinary
credentials and does not quietly acquire revocation, host authorization, or
privileged access variants.

**Acceptance criteria:**

- Real SSH/agent tests prove a successful MFA login gets a persisted-CA
  certificate whose signature, serial, key ID, principals, and validity are
  inspectable through public SSH interfaces.
- Negative tests cover CA mismatch/malformed state, invalid duration, serial
  collision, identity/group failure, persistence/signing failure, and agent
  failure; all fail closed.
- The CLI adds only the stated ordinary CA commands, not rotation, revoke,
  reconcile, host authorization, user deletion, daemon lifecycle, database or
  config override, temporary/emergency, root/service-account, or production
  identity-provider commands.
- The schema has no revocation/KRL-maintenance or production-host policy tables;
  the empty KRL is not treated as revocation evidence or distributed by ski.
- The formatter, linter, type checker, integration tests, and systemd checks
  pass. Documentation says host trust is Epic 5 work.
