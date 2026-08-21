# R8 — Shared public-behaviour test fixtures

## Scope

Extract only demonstrated integration-test setup duplication. Fixtures keep
real AsyncSSH, SQLite, Unix-agent, and CLI boundaries in the test path; they
must not become a mock-based test framework or hide scenario assertions.

## 1. Isolated ssh-agent lifecycle fixture

**Outcome.** Agent tests express an observable agent scenario without manually
duplicating process startup, environment isolation, and teardown.

**Behavioural tests, in order:**

1. A test using the fixture starts an isolated real `ssh-agent`, exposes its
   socket to a supplied SSH client operation, and leaves no agent process after
   the context closes.
2. An exception in the scenario still closes the client and agent reliably.
3. Migrate one existing ordinary-agent behaviour test without changing its
   assertion or credential semantics.

**Implementation boundary.** Add one small async test-support context manager;
do not change production agent code or absorb agent assertions into the helper.

**Done when.** Duplicated lifecycle code begins to disappear and tests still
prove real agent behaviour through their existing public paths.

## 2. MFA SSH client fixture

**Outcome.** Tests share one explicit keyboard-interactive client helper while
each test retains its own credentials, connection intent, and assertions.

**Behavioural tests, in order:**

1. A supplied username, password, TOTP response, host/port, and forwarding
   choice perform the same successful authenticated SSH exchange as today.
2. Wrong password, wrong TOTP, and backend failure tests retain their distinct
   setup but observe the same normalized failure result.
3. Migrate one duplicated client at a time from two test modules.

**Implementation boundary.** Keep the helper in test support and parameterize
only external client input; do not add a production authentication abstraction.

**Done when.** Repeated keyboard-interactive plumbing is centralized without
making authentication failure assertions indirect.

## 3. Enrolled runtime fixture

**Outcome.** Ordinary happy-path integration tests can enroll a demo identity,
start a configured runtime, and clean it up through one readable fixture.

**Behavioural tests, in order:**

1. The fixture creates a temporary real database and configured issuer with an
   explicitly supplied enrolled user and group state.
2. A normal authenticated issuance test using it observes the existing public
   certificate/agent outcome.
3. Closing the fixture releases the listener, database lock, agent, and other
   resources so a subsequent runtime can start.

**Implementation boundary.** Reuse public CLI/store/runtime setup where
practical. Keep unusual enrollment and scenario steps visible in individual
tests.

**Done when.** Repeated happy-path scaffolding is reduced while lifecycle
coverage remains real and explicit.

## 4. Raw SQLite corruption test helper

**Outcome.** Tests can create malformed persisted state without treating a
production private connection as a test API.

**Behavioural tests, in order:**

1. A corruption test modifies a temporary database by its path and confirms
the public state/runtime interface fails closed as it did before.
2. Migrate one test which previously reached `StateDatabase._connection`.
3. Confirm test support contains the only intentional raw SQLite access.

**Implementation boundary.** The helper is test-only and accepts a path; it
does not leak production objects or add a public production escape hatch.

**Done when.** Corruption scenarios remain covered and private production
attributes are not test dependencies.

## 5. Capability-focused integration test modules

**Outcome.** Large integration test files are split only after their shared
setup is extracted, preserving clear user-visible behaviour ownership.

**Behavioural tests, in order:**

1. Move one coherent group of tests (for example successful authenticated
injection) into a capability-named module with unchanged assertions.
2. Run the complete affected capability suite and prove collection remains
stable.
3. Repeat only where a resulting module has a clearer public behaviour focus.

**Implementation boundary.** No production changes and no mechanical
line-count-driven split.

**Done when.** Each integration module has a clear public-behaviour focus and
shared setup does not obscure its scenarios.
