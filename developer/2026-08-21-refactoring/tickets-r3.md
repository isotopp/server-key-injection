# R3 — Issuer identity interfaces and demo administration

## 1. Characterize runtime identity capabilities

**Outcome.** The daemon's smallest identity need is observable authentication,
canonical identity lookup, and group snapshots.

**Behavioural tests, in order:**

1. An authenticated SSH exchange succeeds with a backend providing only those
   read capabilities.
2. A backend failure denies login with the current normalized failure response.
3. Runtime request handling cannot depend on user/group mutation methods.

**Implementation boundary.** Characterization tests and external-interface
test doubles only; do not mock application modules.

## 2. Introduce secret-free presentation records

**Outcome.** `user show` and `user list` receive records which cannot contain a
password verifier or TOTP secret.

**Behavioural tests, in order:**

1. `user list` retains its existing output from a secret-free summary record.
2. `user show` retains its existing output from a secret-free detail record.
3. Not-found and malformed-identity output/status remain unchanged.

**Implementation boundary.** Keep secret-bearing SQLite records internal to
authentication. Do not alter CLI syntax or add output fields.

## 3. Define stable issuer read protocols

**Outcome.** Authentication, canonical lookup, and group snapshots are narrow,
documented structural protocols.

**Behavioural tests, in order:**

1. Move one runtime caller to the appropriate protocol and preserve a real SSH
   exchange.
2. Move remaining runtime/read-only callers one at a time.
3. Confirm password and TOTP failures remain indistinguishable.

**Implementation boundary.** These protocols are the supported Python
extension surface. Do not preserve unrelated legacy imports.

## 4. Separate SQLite demo administration protocols

**Outcome.** User/group mutation is optional and only the SQLite demo adapter
implements it.

**Behavioural tests, in order:**

1. Move one user mutation command to an optional user-administration capability
   while preserving CLI output, notification, and errors.
2. Move group and membership commands one family at a time.
3. A read-only backend used for a mutation command fails safely before partial
   work.

**Implementation boundary.** Do not add LDAP/AD writes or a directory admin
API.

## 5. Move SQLite identity SQL behind R1's boundary

**Outcome.** Identity operations use public persistence APIs, retaining Argon2
and TOTP policy in the identity adapter.

**Behavioural tests, in order:**

1. Move one authentication lookup and preserve its public SSH result.
2. Move group snapshots and safe presentation queries.
3. Move optional demo administration persistence operations.

**Implementation boundary.** Depend on R1; do not reopen private connection
access.

## 6. Document the read-only adapter contract

**Outcome.** LDAP, Active Directory, and custom adapter authors know the
required data, safe errors, and read-only security boundary.

**Behavioural tests, in order:**

1. Exercise a minimal documented adapter in a runtime integration test.
2. Document canonicalization, authentication, group snapshots, unavailable
   backends, secret handling, and the read-only rule.

**Implementation boundary.** Contract and documentation only; do not add a
network client or concrete production backend.
