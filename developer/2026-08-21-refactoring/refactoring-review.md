# Refactoring review

## Purpose

This review identifies structural changes which can make the current codebase
easier to change without altering its public behaviour. It is intentionally
written as input to a later ticket step: each accepted finding has evidence, a
target boundary, test expectations, and candidate delivery slices.

This is security-relevant software. A refactor is not permission to change
authentication, certificate contents, certificate lifetime, extension policy,
agent ownership rules, persistence ordering, audit semantics, CLI output, or
failure behaviour. A behaviour change discovered while implementing these
findings requires its own reviewed ticket.

## Review method

The review applied the project's TDD guidance and the following design tests:

- preserve behaviour through public-interface tests;
- prefer deep modules with small interfaces;
- separate policy, application workflow, and infrastructure adapters;
- keep dependency direction explicit;
- remove duplication which can cause security decisions to diverge;
- avoid splitting files solely to satisfy a line-count target.

The review covered all production modules under `src/ski/`, their dependencies,
and the test support under `tests/`. It did not propose new features from later
architecture epics.

## Baseline

| Module | Lines | Current responsibilities |
| --- | ---: | --- |
| `src/ski/state.py` | 1,057 | database ownership, locking, schema creation and migration, host-key generation and validation, CA records, certificate records, event records, integrity verification, transactions |
| `src/ski/cli.py` | 753 | parser construction, command dispatch, service loop, CA workflows, identity workflows, rendering, error translation, service notification |
| `src/ski/identities.py` | 488 | identity contracts, public records, validation, password hashing, TOTP verification, all SQLite identity and group operations |
| `src/ski/runtime.py` | 422 | startup, resource construction, reload, shutdown, signal handling, request tracking, issuance request orchestration, event emission |
| `src/ski/server.py` | 293 | AsyncSSH listeners, keyboard-interactive authentication, session protocol, user-facing response rendering |
| `src/ski/credentials.py` | 265 | ordinary signing, issuance persistence service, serial retry, failure logging, and legacy disposable tracer credentials |

Line count is evidence of accumulated responsibility, not an acceptance
criterion. `ca.py`, `configuration.py`, `environment.py`, `journal.py`, and
`notify.py` remain reasonably cohesive at their current size.

## Non-negotiable regression contract

Every ticket generated from this review must identify the public behaviour it
preserves and prove it with one vertical red-green-refactor cycle at a time.
Across the epic, the following must remain true:

- existing SQLite schema versions open or migrate exactly as documented;
- daemon single-instance locking, startup cleanup, reload, and bounded shutdown
  retain their current ordering;
- password and TOTP failures remain indistinguishable and fail closed;
- canonical identity and group validation remains unchanged;
- ordinary certificates remain Ed25519, contain the same principals and
  extensions, and remain valid for exactly 25 hours;
- agent replacement removes only a credential proven to be owned by this
  issuer and preserves unrelated identities;
- prepare, agent-add, durable commit, compensation, and failure-event ordering
  does not change accidentally;
- CA private keys, generated user private keys, password verifiers, TOTP
  secrets, and agent payloads never appear in output, errors, or logs;
- CLI command forms, exit status, redaction, and stdout/stderr text remain
  stable unless separately approved;
- the full formatter, linter, type checker, and test suite pass after every
  refactoring ticket.

## Finding R1 — Split the SQLite state monolith by persistence domain

**Priority:** High

**Evidence.** `StateDatabase` begins at `src/ski/state.py:194` and owns the
connection, filesystem lock, migrations, three table families, host private-key
generation, CA and certificate records, event queries, integrity verification,
and transaction control. Schema evolution is embedded in one conditional
method at `src/ski/state.py:258`. Host-key operations begin at line 424, CA
operations at line 510, certificate operations at line 618, and event
operations at line 785. `SqliteIdentityStore` crosses the boundary seven times
through `StateDatabase._connection`, starting at `src/ski/identities.py:187`.

The current CA log command also calls `list_events()`, filters the complete log
in `src/ski/cli.py:321`, and only then limits output to 100 records. The public
output is bounded, but the database read and memory use are not. Integrity
verification performs repeated linear searches across certificates and events
in `src/ski/state.py:848`.

**Why it matters.** Unrelated storage changes collide in one module, domain
adapters depend on a private connection, and future revocation/rotation tables
will make the class grow further. The private access is a concrete signal that
the public persistence boundary is missing. In-memory filtering also puts query
policy in the CLI rather than the persistence adapter.

**Recommendation.** Keep a small SQLite ownership/unit-of-work component for
file permissions, locking, connection setup, transaction control, and close.
Move ordered schema migrations into a dedicated migration module. Put host-key,
demo-identity, and CA/audit persistence behind cohesive adapters which receive
the unit of work through a public interface. Query filtering, stable ordering,
and limits belong in the relevant adapter.

Do not create a generic repository framework. The useful boundary is a small
number of domain-specific operations with validated records, not a wrapper for
every SQL statement.

**Candidate ticket slices.**

1. Characterize opening new and existing schema versions, ownership locking,
   rollback, and idempotent close through current public APIs.
2. Extract ordered schema migrations without changing schema version 4 or any
   SQL definition.
3. Expose a public SQLite unit-of-work/query boundary and remove all production
   access to `StateDatabase._connection`.
4. Extract identity persistence, followed by host-key persistence, then CA and
   audit persistence; move one cohesive operation set per ticket.
5. Add repository-level CA event filters and a SQL limit while preserving the
   current stable event order and redacted CLI output.
6. Replace nested integrity scans with indexed lookups or set-based checks,
   preserving every existing rejection.

**Done when.** No production module accesses a private database connection;
`state.py` no longer owns every persistence domain; migration compatibility and
transaction atomicity remain covered through public APIs; a bounded log request
does bounded storage work.

## Finding R2 — Make the CLI a thin adapter over command workflows

**Priority:** High

**Evidence.** `build_parser()` spans `src/ski/cli.py:38-127`, command
implementations occupy most of lines 169-639, and `main()` contains a long
conditional dispatcher from line 641 onward. The module opens the identity
store twelve times, calls `notify_after_mutation()` nine times, closes a
database sixteen times, and repeats the committed-but-notification-failed text
seven times. CA initialization transaction compensation and TOTP enrollment
material generation are application workflows implemented directly in the CLI
adapter.

**Why it matters.** Parser, presentation, resource lifetime, mutation policy,
and domain workflow change for different reasons. Repeated close/notify/error
paths make it easy for a new administrative command to omit a reload, report a
durable mutation as failed, leak a backend error, or close a resource
differently. The current module will grow with every later CA/KRL command.

**Recommendation.** Keep `ski.cli` responsible for building the top-level
parser, selecting injected process dependencies, invoking one handler, and
mapping a safe application result to process output. Move CA, user/group, and
service handlers into cohesive command modules. Introduce a small command
context for output, concealed input, notifier, and database/store acquisition.
Centralize the post-commit notification result without hiding command-specific
success text.

Application services, rather than argparse handlers, should own multi-resource
workflows such as CA file installation plus database registration. Avoid a
class per subcommand and avoid a global command registry; simple functions with
explicit dependencies are sufficient.

**Candidate ticket slices.**

1. Add characterization tests for parser forms, command output, exit status,
   redaction, stopped-service success, and notification failure.
2. Introduce a context-managed command resource boundary and migrate one
   read-only identity command.
3. Centralize post-commit notification handling and migrate one identity
   mutation before moving the remaining user/group commands.
4. Extract CA read-only commands and their filter/render helpers.
5. Move CA initialization compensation into an application service and leave
   the CLI handler as parse/invoke/render.
6. Replace the conditional dispatcher with parser-selected handlers while
   preserving `main()` as the console entry point.

**Done when.** `ski.cli` is a small composition and presentation layer;
commands do not duplicate database lifetime or notification policy; all
existing CLI tests continue to exercise the same public `main()` interface.

## Finding R3 — Separate runtime identity use from demo administration

**Priority:** High

**Evidence.** `IdentityStore` exposes fifteen abstract methods at
`src/ski/identities.py:78-139`, combining authentication, group snapshots,
secret-bearing user retrieval, user administration, and group administration.
`UserRecord` contains both password verifier and TOTP secret at lines 60-68,
and `get_user()` returns that record to read-only administrative callers. The
SQLite implementation combines Argon2, TOTP policy, data validation, and SQL in
one 333-line class.

**Why it matters.** A production identity provider used by the daemon should
not have to implement demo-only administration methods. Read-only CLI code can
currently receive secrets it must remember not to render. The wide interface
is shallow for both runtime and tests, and it obscures which capabilities a
caller is allowed to use.

**Recommendation.** Define narrow structural protocols for issuer
authentication/group lookup and for demo administration. Use safe summary/view
records for list/show operations. Keep password verifiers and TOTP secrets in a
SQLite-adapter-internal record. The SQLite adapter may implement both protocols,
while a future production adapter implements only the runtime contract.

Do not combine password and TOTP into a new authentication behaviour during
this refactor. The current two-prompt exchange and failure normalization are
part of the regression contract.

**Candidate ticket slices.**

1. Characterize the runtime's smallest required identity interface through an
   authenticated SSH exchange and backend-failure denial.
2. Introduce safe user detail and summary records, then migrate `user show` and
   `user list` away from secret-bearing `UserRecord`.
3. Split runtime and administration protocols and narrow each caller's type.
4. Move SQLite identity SQL behind the persistence boundary from R1 while
   keeping Argon2/TOTP policy in the identity adapter.

**Done when.** Runtime code cannot call demo administration methods; list/show
commands cannot receive authentication secrets; a production adapter has a
small issuer-facing contract; all authentication failures remain fail closed.

## Finding R4 — Give one workflow ownership of issuance and agent compensation

**Priority:** High; security-sensitive

**Evidence.** `OrdinaryIssuanceService.issue()` at
`src/ski/credentials.py:175` owns serial retry and failure recording, but the
runtime path does not use it. `OrdinaryAgentInjector.handle()` at
`src/ski/injection.py:63` independently implements another retry loop,
prepare/add/commit ordering, compensation, and failure recording. Both detect a
duplicate serial by matching the text `"serial is already recorded"`.
`record_failure()` and agent cleanup suppress every exception at
`src/ski/credentials.py:217` and `src/ski/injection.py:109`.

**Why it matters.** There are two competing definitions of the issuance
workflow, and only one matches the agent-first compensation requirements. A
wording change to an exception can silently disable retry. Broadly suppressed
cleanup/audit failures are difficult to distinguish from successful
compensation. This is a high-risk place for later revocation and audit work to
attach to the wrong path.

**Recommendation.** Establish one application workflow which owns serial
allocation retry, credential preparation, agent replacement, durable success
commit, compensation, and failure-event attempts. Give it narrow signer,
agent, and issuance-recording collaborators. The agent adapter should contain
AsyncSSH operations and ownership checks, not persistence policy. Replace
message matching with a specific duplicate-serial exception.

Keep the current externally observable failure response. If cleanup or audit
failure needs a new operator event, make that a separately accepted behaviour
ticket rather than smuggling it into the refactor.

**Candidate ticket slices.**

1. Characterize the complete successful ordering and every existing
   compensation branch through the forwarded-agent interface.
2. Add a typed duplicate-serial error at the persistence boundary and migrate
   one retry path.
3. Remove the unused competing `OrdinaryIssuanceService.issue()` orchestration
   or make it the single workflow; do not leave two public paths.
4. Extract the AsyncSSH agent adapter and move the state machine into one
   application service.
5. Represent cleanup and failure-event outcomes internally so they cannot be
   silently mistaken for successful work, without changing session output.

**Done when.** Exactly one production workflow defines issuance ordering;
duplicate serials use a typed error; tests prove unrelated keys survive and no
uncommitted credential remains after failure.

## Finding R5 — Reduce `ServiceRuntime` to a lifecycle facade

**Priority:** Medium

**Evidence.** `ServiceRuntime` starts at `src/ski/runtime.py:42`, initializes
fourteen mutable fields, constructs every concrete runtime dependency in
`start()` at lines 111-179, validates reloads, installs signal handlers, tracks
in-flight tasks, coordinates shutdown, handles certificate requests, and emits
journal events. Startup cleanup and normal shutdown reset overlapping resource
sets in separate methods.

**Why it matters.** The class is the composition root, lifecycle manager,
signal controller, request application service, and logging facade at once.
Adding KRL reconciliation or production identity adapters will lengthen startup
and multiply partial-initialization states. Testing requires injecting some
factories while other concrete dependencies are created internally.

**Recommendation.** Retain `ServiceRuntime` as the deep public lifecycle facade
with `start`, `reload`, and `close`. Build an immutable `RuntimeResources`
bundle which owns the successfully constructed state, CA, issuer, and issuance
workflow, and provides one cleanup path. Extract authenticated request handling
into an application service. Keep signal/control-loop wiring at the executable
boundary or in a dedicated controller.

Do not expose every internal component as a new public property. The goal is a
smaller interface and fewer invalid states, not more dependency injection
parameters.

**Candidate ticket slices.**

1. Characterize partial-start cleanup and idempotent/concurrent close.
2. Introduce a resource bundle and use one cleanup implementation for failed
   startup and normal shutdown.
3. Extract authenticated request processing with an explicit safe event sink.
4. Move signal/control-event wiring out of resource construction while
   preserving `uv run ski serve` behaviour.
5. Narrow runtime properties and factory types after callers have migrated.

**Done when.** Runtime construction has one resource ownership model and one
cleanup path; request processing and signal wiring are independent of resource
acquisition; start/reload/close behaviour remains unchanged.

## Finding R6 — Isolate or retire the legacy tracer path

**Priority:** Medium

**Evidence.** The live runtime still creates `TracerAgentInjector`, exposes
`_handle_tracer_request`, and constructs `TracerIssuer` with both anonymous and
authenticated handlers (`src/ski/runtime.py:24-26`, 75, and 149-150). With the
runtime's mandatory identity store, the anonymous handler is not selected after
a successful login. `server.py` still describes the listener as an in-memory
test issuer, and `credentials.py` describes itself as disposable even though
ordinary issuance is now its primary responsibility. Tracer names occur across
the live server, runtime, credentials, and injection modules.

**Why it matters.** Legacy names conceal which path is authoritative, and the
unused runtime path increases the number of credential behaviours reviewers
must reason about. Later epics could accidentally add production functionality
to a tracer abstraction or preserve dummy behaviour as an unintended public
contract.

**Recommendation.** Decide whether the anonymous tracer remains a supported
developer feature. If not, remove it from `ServiceRuntime` and keep any needed
protocol fixture under test support until its tests are migrated. Rename the
live listener and request types around issuer terminology. If compatibility is
needed, use a temporary alias for one epic rather than maintaining two
implementations.

**Candidate ticket slices.**

1. Prove that `uv run ski serve` uses only the authenticated ordinary path.
2. Remove the anonymous tracer handler and injector from `ServiceRuntime`.
3. Move disposable credential tests behind an explicit test/demo boundary or
   delete them if no longer required.
4. Rename the live server/session types and update stale module documentation,
   retaining a temporary alias only if the open question below requires it.

**Done when.** Production runtime dependencies and names describe the ordinary
issuer path; dummy issuance cannot be reached accidentally; retained demo code
has an explicit owner and lifecycle.

## Finding R7 — Centralize domain policy and use typed domain failures

**Priority:** Medium

**Evidence.** The 25-hour lifetime is defined independently as
`CERTIFICATE_LIFETIME` in `configuration.py:16` and
`ORDINARY_CERTIFICATE_LIFETIME` in `state.py:19`; credentials import the state
constant rather than the runtime configuration value. The canonical username
regular expression appears in `identities.py:19`, `state.py:21`, and inline in
`cli.py:312`. Certificate serial range validation and event/filter grammar are
also represented as primitives in several layers. Duplicate-serial control
flow relies on exception text.

**Why it matters.** These are access-control and certificate invariants. A
future policy edit can update configuration while signing or persistence keeps
the old value. Repeated grammar permits the CLI, identity adapter, and database
decoder to disagree about the same identity.

**Recommendation.** Give certificate policy and canonical identity grammar one
domain-level source of truth. Reuse validation functions at input and
persistence boundaries. Introduce specific exception types for control-flow
conditions such as duplicate serials while retaining safe outer error
translation. Prefer small validated records/functions over a generic `utils`
module or a hierarchy of one-field wrapper classes.

**Candidate ticket slices.**

1. Characterize identity, group, serial, lifetime, and extension edge cases
   through the current public interfaces.
2. Centralize canonical identity/group/principal grammar and migrate one layer
   at a time.
3. Centralize the ordinary certificate lifetime and make configuration,
   signing, and persistence validation consume the same policy value.
4. Add typed persistence errors for duplicate serial and other expected
   conflict conditions, then remove message matching.

**Done when.** Each security-relevant invariant has one authoritative
definition; all boundaries still validate untrusted or persisted data; control
flow does not depend on human-readable error text.

## Finding R8 — Build shared public-behaviour test fixtures

**Priority:** Medium

**Evidence.** `tests/test_authenticated_injection.py` is 579 lines,
`tests/test_runtime.py` is 590 lines, and `tests/test_identity_cli.py` is 504
lines. `ssh-agent` start/stop helpers are duplicated in
`test_injection.py:16-53` and `test_authenticated_injection.py:24-55`.
Near-identical MFA clients exist in three test modules. Tests repeatedly build
the same issuer, user, agent, SSH connection, and teardown nesting, while
`tests/support.py` contains only the runtime environment helper.

**Why it matters.** Large setup blocks obscure the behaviour asserted by each
test and make every protocol change expensive. Manual nested cleanup is easy to
get subtly wrong. Some corruption tests reach into `_connection`, coupling
tests to the implementation boundary which R1 should remove.

**Recommendation.** Add small async context managers/fixtures for a disposable
agent, an enrolled runtime, and an MFA client. Keep scenario actions and
assertions in the test so the fixture does not become a hidden test framework.
Share only demonstrated duplication. Continue to use real AsyncSSH, SQLite,
and agent boundaries for critical paths; do not replace them with internal
mocks.

When a corruption test needs malformed storage, use an explicit raw SQLite test
helper against the database path rather than a production object's private
attribute. Split large test files by user-visible capability only after shared
setup is extracted.

**Candidate ticket slices.**

1. Extract the duplicated agent lifecycle into one async context manager and
   migrate one test at a time.
2. Extract the MFA client and one authenticated connection helper without
   absorbing scenario assertions.
3. Add an enrolled-runtime fixture and migrate repeated happy-path setup.
4. Replace private connection access in corruption tests with an explicit raw
   database test helper.
5. Split integration files by capability when each resulting file has a clear
   public behaviour focus.

**Done when.** Each integration test foregrounds one observable behaviour,
critical tests still cross real public boundaries, teardown is centralized and
reliable, and production private attributes are not test APIs.

## Recommended ticket-generation order

If all findings are accepted, generate tickets in this dependency order:

1. Extract only the test fixtures needed by the first production refactor from
   R8; continue expanding them vertically as later tickets need them.
2. Centralize domain policy and typed conflict errors from R7.
3. Establish the SQLite unit-of-work and domain persistence boundaries from R1.
4. Narrow runtime and administration identity contracts from R3.
5. Consolidate the issuance/agent workflow from R4.
6. Move application workflows out of the CLI and split command adapters from
   R2.
7. Simplify runtime resource ownership and request handling from R5.
8. Remove or isolate the tracer path from R6 once its compatibility decision is
   explicit.

Each ticket should move one vertical behaviour-preserving slice, run the full
suite, and be committed before the next ticket. Avoid a ticket which merely
creates empty packages or moves all files before behaviour is exercised.

## Open questions

1. **Is the anonymous disposable tracer still a supported developer interface,
   or may it be removed once the ordinary issuer smoke test covers the same
   protocol path?**

   **Recommendation:** remove it from `ServiceRuntime`. Retain a clearly named
   test fixture temporarily only where it still provides distinct coverage.
   The ordinary authenticated path is now the shipped behaviour, and keeping a
   second runtime issuance mode increases security review cost.

2. **Must external Python callers retain imports such as `TracerIssuer`,
   `StateDatabase`, and `IdentityStore`, or is the CLI the only compatibility
   surface?**

   **Recommendation:** treat the CLI and SSH behaviour as stable; treat these
   Python names as internal for now. If external callers exist, keep explicit
   one-epic aliases and removal notes instead of freezing the current module
   layout indefinitely.

3. **Must databases created by every prior schema version remain upgradeable,
   or may pre-production databases be recreated?**

   **Recommendation:** preserve the current version 1 through 4 upgrade path.
   The cost is small today, and migration extraction is safer when tested
   against real prior versions. Reconsider only through a deliberate data
   compatibility decision.

4. **Should the future production identity backend expose administration
   through this CLI?**

   **Recommendation:** no. Keep demo SQLite administration as a separate
   capability. The daemon-facing production identity protocol should contain
   only authentication and group snapshot operations, leaving external
   directory administration to its authoritative system.

## Suggestions

- Document a dependency rule for the target structure: CLI and SSH adapters
  depend on application services; application services depend on domain policy
  and narrow protocols; SQLite, AsyncSSH, systemd, and journald implementations
  are outer adapters. Domain policy must not import CLI or runtime modules.
- Add a small architecture regression test, using the standard library if
  practical, which rejects production access to `StateDatabase._connection`
  and duplicate definitions of core certificate policy. Do not add a heavy
  architecture framework for two rules.
- Use module size and repeated setup as review triggers, not hard line-count
  gates. Cohesion and dependency direction are the acceptance criteria.
- Do not add a migration framework yet. Ordered stdlib SQLite migrations are
  adequate for the current single-database deployment; revisit tooling only
  when another database backend or a genuinely complex migration requires it.
