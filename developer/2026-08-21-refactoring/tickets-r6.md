# R6 — Remove the obsolete Epic 1 tracer

## 1. Prove the ordinary authenticated path is authoritative

**Outcome.** `ski serve` issues only through the authenticated ordinary path.

**Behavioural tests, in order:**

1. A successful login issues an ordinary credential through the public SSH and
   agent path.
2. An unauthenticated connection cannot reach a disposable tracer credential.
3. Relevant SSH/agent tracer coverage is identified under the ordinary path
   before tracer tests are removed.

**Implementation boundary.** Characterization only; do not remove code yet.

## 2. Remove anonymous tracer runtime handling

**Outcome.** `ServiceRuntime` no longer creates or routes to an anonymous
tracer handler/injector.

**Behavioural tests, in order:**

1. Remove one anonymous-handler route while authenticated issuance remains
   green.
2. Remove tracer injector construction and prove unsuccessful connections do
   not load an identity.
3. Delete the now-unreachable runtime hook.

**Implementation boundary.** No compatibility alias: CLI, SSH behaviour, and
R3 interfaces are the only stable surfaces.

## 3. Delete disposable credential implementations and tests

**Outcome.** Test-only tracer code does not preserve an obsolete runtime
credential mode.

**Behavioural tests, in order:**

1. Migrate any still-relevant tracer protocol assertion to an ordinary
   authenticated test.
2. Delete tracer-only credential/injection implementation and obsolete tests.
3. Confirm ordinary tests retain unrelated-agent-key and failure coverage.

**Implementation boundary.** Do not delete coverage merely because it names a
tracer; first preserve its real observable behaviour elsewhere.

## 4. Rename ordinary issuer terminology and documentation

**Outcome.** Production names and current documentation describe the ordinary
issuer rather than an in-memory disposable tracer.

**Behavioural tests, in order:**

1. Rename one live listener/session/request type while preserving SSH
   behaviour.
2. Update module docstrings, README, and architecture text for actual current
   behaviour.
3. Add a focused repository regression test if useful to prevent stale
   production tracer references without constraining historical artifacts.

**Implementation boundary.** Do not rewrite historical epic artifacts; update
only current operation/developer documentation.
