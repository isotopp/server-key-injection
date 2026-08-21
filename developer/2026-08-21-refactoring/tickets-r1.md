# R1 — SQLite persistence boundaries

## Scope

Split persistence by cohesive domain while retaining one SQLite owner for file
permissions, locking, connection lifecycle, transactions, and close. Schema
version 4 is the only supported historical baseline; versions 1–3 may fail
safely and newer unknown schemas must fail safely.

## 1. Schema-version and ownership characterization

**Outcome.** The supported baseline and storage lifecycle are public,
regression-protected behaviour.

**Behavioural tests, in order:**

1. A new temporary database and a version-4 database open successfully.
2. Version-1 through version-3 and unknown newer schemas fail safely without
silent replacement or partial migration.
3. Single-instance locking, rollback, and idempotent close retain their
existing public behaviour.

**Implementation boundary.** Characterization only; do not rewrite SQL.

**Done when.** The approved version-4 compatibility contract is executable.

## 2. Ordered version-4 migration baseline

**Outcome.** Migration ownership is explicit and future migrations are ordered
without retaining unpublished historical branches.

**Behavioural tests, in order:**

1. Extract the version-4 schema creation/migration operation while a fresh
database has exactly its current schema and public behaviour.
2. Remove version-1 through version-3 migration branches and prove they are
rejected safely.
3. Add one testable ordered-migration dispatch seam for a future version,
without adding a migration framework or an actual new schema version.

**Implementation boundary.** A dedicated migration module may depend on the
SQLite owner; domain adapters must not own schema evolution.

**Done when.** Version-4 creation is unchanged and future migration ordering
is isolated and explicit.

## 3. Public SQLite unit-of-work boundary

**Outcome.** Domain persistence uses a public, narrow SQLite work boundary
instead of `StateDatabase._connection`.

**Behavioural tests, in order:**

1. Migrate one identity operation through the new public boundary and retain
its existing CLI/SSH behaviour.
2. Migrate remaining production private-connection consumers one at a time.
3. Add a lightweight architecture test which rejects production references to
`StateDatabase._connection`.

**Implementation boundary.** Do not create generic repositories or expose
arbitrary SQL to application code.

**Done when.** Production private-connection access is absent and transaction
ownership remains centralized.

## 4. Identity persistence adapter

**Outcome.** SQLite identity rows live behind a cohesive adapter while Argon2
and TOTP policy remains in the identity layer.

**Behavioural tests, in order:**

1. Move one user lookup/authentication operation and prove the SSH failure
normalization is unchanged.
2. Move group snapshot and membership operations through public records.
3. Move demo administration persistence operations without exposing secrets.

**Implementation boundary.** Coordinate the public contracts with R3; do not
change identity semantics.

**Done when.** `state.py` no longer contains identity-domain SQL and the
identity adapter does not require private connection access.

## 5. Host-key and CA/audit adapters

**Outcome.** Host-key and CA/certificate/event persistence each have cohesive
domain APIs.

**Behavioural tests, in order:**

1. Move host-key creation/loading and preserve secure file, validation, and
runtime startup behaviour.
2. Move active-CA and certificate record operations while preserving issuance
atomicity and serial uniqueness.
3. Move event recording/query operations while retaining append-only semantics
and redaction.

**Implementation boundary.** Each adapter receives the unit of work; the SSH
server continues to use application services rather than SQL rows.

**Done when.** Persistence domains can evolve independently without a new
generic data-access layer.

## 6. Bounded CA log queries and integrity verification

**Outcome.** Audit reads apply filters, stable order, and limits in persistence
and integrity checks avoid avoidable repeated scans.

**Behavioural tests, in order:**

1. The public CA log command returns the same stable, redacted first 100
matching events while persistence reads only the bounded result.
2. Invalid filters retain current safe CLI rejection.
3. Replace nested integrity lookups with indexed/set-based checks and prove
every existing corruption rejection remains.

**Implementation boundary.** Preserve output text and audit meaning; do not
alter retention, revocation, or event policy.

**Done when.** Bounded requests do bounded storage work and integrity checks
remain fail closed.
