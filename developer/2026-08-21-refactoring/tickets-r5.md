# R5 — Runtime lifecycle facade

## 1. Characterize lifecycle edges

**Outcome.** Partial-start cleanup plus idempotent and concurrent close are
protected before resource ownership changes.

**Behavioural tests, in order:**

1. A startup failure after each acquired resource cleans up prior resources.
2. Normal close releases the same resources in the existing safe order.
3. Repeated/concurrent close remains safe and bounded.

**Implementation boundary.** Test observable release, listener reuse, and safe
events; do not assert mutable-field resets.

## 2. Introduce immutable runtime resources

**Outcome.** Successfully acquired database, CA, issuer, and issuance workflow
are owned by one immutable resource bundle with one cleanup path.

**Behavioural tests, in order:**

1. Route normal startup/close through the bundle and retain lifecycle tests.
2. Route failed startup through the same cleanup operation.
3. Verify no partially constructed resource bundle becomes visible to requests.

**Implementation boundary.** Keep `ServiceRuntime.start`, `reload`, and
`close` as the deep public lifecycle interface.

## 3. Extract authenticated request processing

**Outcome.** Request application work is separate from resource acquisition and
receives an explicit safe event sink.

**Behavioural tests, in order:**

1. Move one successful authenticated request path and preserve SSH/agent
   output and issuance outcome.
2. Move one authentication or issuance failure path and retain fail-closed
   result/event fields.
3. Migrate remaining request paths.

**Implementation boundary.** Do not expose every resource as a public runtime
property or change auth/certificate policy.

## 4. Separate signal/control-loop wiring

**Outcome.** Signal handlers and control events no longer participate in
resource construction.

**Behavioural tests, in order:**

1. Move one shutdown control path and retain bounded SIGTERM/SIGINT behaviour.
2. Move reload control wiring and retain SIGHUP validation/order.
3. Verify `uv run ski serve` keeps application-owned listener behaviour.

**Implementation boundary.** Do not add systemd socket activation or change
Type=simple deployment.

## 5. Narrow runtime properties and factories

**Outcome.** Callers see only lifecycle and necessary external boundaries;
internal construction is not a public API.

**Behavioural tests, in order:**

1. Remove one migrated public/internal property and retain public runtime
   behaviour.
2. Narrow one factory type after its callers have moved.
3. Repeat only for demonstrated unnecessary exposure.

**Implementation boundary.** No compatibility aliases are needed for internal
Python imports.
