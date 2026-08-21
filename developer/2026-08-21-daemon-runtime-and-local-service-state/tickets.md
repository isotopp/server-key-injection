# Daemon runtime and local service state — tickets

## Implementation rules

Implement these tickets in order. During the code-generation step, begin each
ticket with one public behavioural test, make only that test pass, and then add
the next behaviour. Do not write a ticket's complete test suite before its
implementation. Refactor only while the suite is green.

Tests exercise public CLI, configuration, service, state, and logging
interfaces. Use real temporary files, SQLite databases, sockets, subprocesses,
and SSH connections where practical. Substitute only operating-system
boundaries such as journald and systemd; do not mock application modules or
assert private call sequences.

Run `uv run ruff format`, `uv run ruff check --fix`, `uv run ty check`, and
`uv run pytest` before completing each ticket. Commit each completed ticket
with the git-commit skill before starting the next one.

This epic retains the Epic 1 disposable CA and one-hour `test-` credentials. It
must not introduce persistent CA keys, real certificate records,
password/TOTP identities, groups, KRLs, or production-host authorization.

## 1. Validated runtime configuration and CLI contract

**Stories.** US-1, US-2, and the CLI surface decisions.

**Outcome.** `ski serve` starts from one immutable, validated configuration
snapshot while `--help` and `--version` remain usable without service state.

**Behavioural tests, in order:**

1. Loading runtime configuration from controlled paths selects the first of
   `./.env`, `$HOME/.ski.env`, and `/etc/ski/env`, while a supplied exported
   environment baseline takes precedence without modifying `os.environ`.
2. A valid `SKI_CA_DATABASE` and explicit `--bind`/`--port` values produce one
   immutable service configuration snapshot containing its source metadata.
3. Missing database configuration, a missing or non-writable parent directory,
   an invalid bind address, and ports outside `1..65535` fail before service
   startup with errors which name the setting but not its value.
4. `ski serve` retains `--bind *` and `--port 22` as defaults; explicit IPv4 and
   IPv6 addresses are accepted.
5. `ski --help`, `ski serve --help`, and `ski --version` do not require a
   database or load the service runtime.

**Implementation boundary.** Replace mutation-oriented dotenv loading in the
service path with a configuration loader which accepts an explicit exported
environment baseline and returns an immutable value. Parsing a dotenv file
must not pollute the baseline used by a later reload. Keep bind and port as CLI
settings and the database path as `SKI_CA_DATABASE`; add no `--config`,
`--database`, or lifecycle command. Retain the existing environment search
helper where it remains useful.

Design the configuration loader as a deep module: callers provide CLI startup
values and receive either a complete snapshot or one redacted configuration
error. Do not let request handling read configuration directly from
`os.environ`.

**Done when.** CLI and configuration tests demonstrate precedence, validation,
immutability, redaction, and the exact bounded command surface without opening
a socket or database.

## 2. Native journald event boundary

**Stories.** US-4 and the journald decision in US-7.

**Outcome.** Service code emits typed operational events through a small
logging interface whose production implementation submits native, queryable
journald fields.

**Behavioural tests, in order:**

1. An in-memory event sink receives one complete service event with standard
   message/priority data and stable `SKI_` fields, establishing the public
   logging contract without systemd.
2. The journald sink passes `MESSAGE`, `PRIORITY`, `SYSLOG_IDENTIFIER`,
   `SKI_EVENT`, and an optional `SKI_REQUEST_ID` as native fields to a
   substituted journal API boundary; it does not serialize JSON into
   `MESSAGE`.
3. Event-specific fields are allowlisted and normalized for the journald API;
   arbitrary fields, complete environment values, exception representations,
   private-key material, and agent payloads cannot be supplied through the
   public logging interface.
4. Startup, ready, reload accepted/rejected, shutdown requested/completed,
   listener failure, database failure, and tracer request outcome have stable,
   distinct event names and appropriate journal priorities.
5. A non-systemd development run can use an explicit console sink, while the
   Linux systemd deployment selects the journald sink and reports journal
   initialization failure without exposing sensitive state.

**Implementation boundary.** Add `systemd-python` as the accepted Linux
runtime dependency, guarded by an appropriate platform marker so the project
remains installable in non-Linux development environments. Isolate its import
and API calls in the journald adapter. Application code depends only on the
event sink interface; tests substitute the external journal API or use the
in-memory sink rather than mocking application logging code.

Use trusted metadata supplied by journald for process, user, and unit identity.
Do not duplicate those values as caller-controlled application fields. This
ticket defines operational events only; the later SQLite CA log remains a
separate audit record.

**Done when.** Tests prove that production events are native journal fields,
unsafe data has no logging path, and the suite runs without a journal daemon.
The dependency and lockfile are current.

## 3. Foundational SQLite state and single-instance ownership

**Stories.** US-3.

**Outcome.** The daemon can create or open versioned foundational SQLite state
and exclusively own one service instance without preventing short
administrative database transactions.

**Behavioural tests, in order:**

1. Opening a configured path for the first time creates a protected SQLite
   database with the supported foundational schema version and no CA,
   certificate, identity, group, revocation, or KRL tables.
2. Reopening the database is idempotent; opening a database with a newer schema
   version fails closed without changing it.
3. The public transaction boundary commits a successful short write and rolls
   back a failed write, with foreign keys enabled and a finite busy timeout on
   every connection.
4. Holding daemon ownership for one database prevents a second daemon owner
   from acquiring it before listener startup, including when the contenders
   use different bind settings.
5. An administrative connection can complete a short transaction while daemon
   ownership is held, and ownership can be reacquired after the first owner
   closes.
6. A failed open or initialization leaves no held advisory lock and no partially
   migrated schema. Newly created database and lock files are not
   group/world-readable.

**Implementation boundary.** Use Python's standard-library `sqlite3` module and
a non-destructive advisory lock associated with the configured database. The
lock coordinates daemon instances only; it must not lock administrators out of
SQLite. Keep migrations explicit and transactional. First service startup may
create the SQLite container and foundation, while the later `ski ca init`
command remains responsible for CA material and CA records.

Expose resource ownership through context-managed public boundaries so closure
and rollback are natural in tests and runtime code. Tests may construct an
unsupported database as setup, but they verify behavior through the state
interface rather than querying implementation tables after application
operations.

**Done when.** Temporary-database tests prove schema compatibility,
transactionality, file protection, concurrent administrative access, and
single-daemon exclusion without leaving lock files held.

## 4. Atomic application-owned listener set

**Stories.** US-2.

**Outcome.** The issuer owns either one requested listener or the complete
IPv4/IPv6 wildcard listener set, with all-or-nothing startup and cleanup.

**Behavioural tests, in order:**

1. Starting on a specific loopback IPv4 address creates only that reachable
   listener and reports its effective address; repeat for IPv6 when available.
2. Starting with `--bind *` explicitly creates listeners for both `0.0.0.0` and
   `::` on the same requested port rather than relying on platform wildcard
   resolution.
3. If the second wildcard bind fails, the first listener is closed, no address
   is reported ready, and the caller receives a redacted listener error.
4. Closing an active listener set is idempotent and releases every socket so
   the same addresses can be rebound.
5. The issuer never consumes `LISTEN_FDS` or another inherited systemd socket;
   its observable listeners are created from the validated CLI configuration.

**Implementation boundary.** Refactor the existing AsyncSSH listener lifecycle
behind one application-owned listener-set interface. Open wildcard families
explicitly and prevent an IPv6 wildcard socket from implicitly consuming the
IPv4 bind. For deterministic failure testing, substitute only the OS/AsyncSSH
listener-opening boundary; verify successful paths with real local sockets and
SSH handshakes.

Retain programmatic ephemeral-port support for tests, but reject port zero at
the public CLI boundary established in Ticket 1. Do not add socket activation,
a `.socket` unit, or inherited-file-descriptor handling.

**Done when.** Real connection tests prove specific and wildcard behavior, and
the forced partial-failure test proves that no listener survives an incomplete
startup.

## 5. Ordered service startup and resource cleanup

**Stories.** US-1, US-3, US-4, and US-9.

**Outcome.** One foreground service runtime acquires configuration, logging,
SQLite ownership, and application listeners in a safe order and releases them
in reverse order after any startup result.

**Behavioural tests, in order:**

1. Starting the public service runtime with valid temporary state makes a real
   tracer SSH listener reachable and emits one ready event containing every
   bound address only after state ownership and listeners are available.
2. Configuration, database, instance-lock, and listener failures each emit the
   corresponding redacted event, exit nonzero through the CLI, and leave no
   later resource active.
3. Closing a started runtime stops new connections, closes SQLite state,
   releases daemon ownership, and emits one completed lifecycle event even
   when closure is requested twice.
4. A complete forwarding-enabled tracer request still injects only a fresh
   one-hour `test-` credential signed by the process-local disposable CA; a
   restart produces a different disposable CA.
5. Inspecting foundational SQLite state through its public schema information
   confirms that tracer requests did not persist a CA key, certificate,
   identity, group, revocation, or KRL record.

**Implementation boundary.** Introduce one service-runtime coordinator with
injected configuration loader and event sink boundaries. It owns the existing
tracer issuer rather than duplicating SSH behavior. Acquisition must complete
before the structured ready event; failures unwind only resources acquired by
that attempt. Keep `Type=simple` semantics: ready is an application event, not
`sd_notify`.

Update the CLI to translate known startup failures into concise nonzero exits.
Do not print exception representations or let expected operational failures
produce tracebacks containing configuration, socket, database, or agent data.

**Done when.** A public-runtime integration test crosses configuration,
SQLite, locking, AsyncSSH, and logging boundaries, and negative tests prove
complete cleanup at every startup stage.

## 6. Bounded graceful shutdown on SIGTERM and SIGINT

**Stories.** US-5.

**Outcome.** systemd stop and a developer interrupt use one idempotent,
bounded shutdown path which stops admission before draining work.

**Behavioural tests, in order:**

1. Requesting shutdown on an idle runtime closes listeners, state, and the
   instance lock in order and emits shutdown-requested and shutdown-completed
   events exactly once.
2. A request already in progress may complete within the configured internal
   grace period after listeners stop accepting new connections.
3. A request which exceeds the grace period is cancelled, its SSH session ends
   without credential data in logs, and all service resources are released.
4. Repeated or simultaneous shutdown requests converge on the same completion
   result without competing cleanup or traceback.
5. Subprocess integration tests send `SIGTERM` and `SIGINT` to `ski serve` and
   observe bounded clean exits and re-bindable listener addresses.

**Implementation boundary.** Track in-flight service request tasks at the
runtime boundary and use one shutdown-completion primitive. The grace period
may be a named internal policy value with a shorter injected value in tests; do
not add a public CLI option in this epic. Install event-loop signal handlers in
the executable service path and keep direct runtime shutdown callable for
portable tests.

Do not cancel requests before listener closure. Cancellation handlers must not
serialize coroutine exceptions or agent state into logs or SSH responses.

**Done when.** Real signal tests and deterministic in-process drain/cancel
tests demonstrate bounded, repeatable cleanup with no orphan process, socket,
database connection, lock, or agent operation.

## 7. Atomic SIGHUP configuration reload

**Stories.** US-6.

**Outcome.** A running issuer can validate and atomically adopt a candidate
configuration snapshot, or retain its complete previous snapshot on any
reload rejection.

**Behavioural tests, in order:**

1. Reloading an unchanged valid environment succeeds, advances the observable
   configuration generation, and emits a reload-accepted event without
   interrupting the listener.
2. A dotenv value loaded at startup is not treated as part of the exported
   environment baseline during reload; changing the selected file produces
   the expected candidate value before startup-only validation.
3. A candidate which is malformed or changes bind address, port, or database
   path is rejected with a restart-required or invalid-configuration event,
   and the entire prior snapshot remains active.
4. A request which begins before an accepted reload keeps its original
   snapshot, while a later request observes the replacement snapshot.
5. Concurrent or repeated reload requests are serialized or coalesced and
   never expose an intermediate snapshot.
6. A subprocess integration test sends `SIGHUP` and confirms that the SSH
   listener remains reachable; the corresponding in-process reload test
   observes the event through the injected sink.

**Implementation boundary.** Capture the original exported environment before
the first dotenv parse and retain it as reload input. Build and validate the
candidate—including the currently empty file-backed-state hook—without
mutating live state, then replace one immutable snapshot reference. Introduce a
request context only as needed to bind a request to that snapshot; do not add
unrelated request attributes.

The listener addresses and database path are never changed by reload. There is
no `ski reload` command and no direct reload network endpoint. `SIGHUP` and the
runtime reload method are the only entry points.

**Done when.** Tests make configuration generations observable through the
public runtime/request boundary and prove success, rejection, request
isolation, signal handling, and reload serialization.

## 8. Post-mutation systemd reload notification boundary

**Stories.** US-8.

**Outcome.** Future mutating commands have one testable boundary which asks an
active local systemd service to reload only after durable work has completed.

**Behavioural tests, in order:**

1. Notifying when `ski.service` is inactive returns success without sending a
   signal or treating the durable mutation as failed.
2. Notifying an active service requests exactly one systemd reload and reports
   success.
3. Failure to query or reload the active service returns a distinct
   operational failure suitable for retry, without invoking or rolling back a
   mutation callback.
4. A transaction-oriented integration fixture demonstrates the ordering:
   notification observes committed SQLite state and is not called after a
   rolled-back transaction.
5. Read-only operations have no notification path, and no public `ski stop`,
   `ski reload`, or `ski status` command appears.

**Implementation boundary.** Define a narrow service-manager interface and a
systemd implementation which addresses only the configured local `ski.service`
unit. Substitute that external boundary in tests; never invoke or signal the
developer's actual service. The notifier has no database mutation callback and
cannot repeat, roll back, or reinterpret already committed work.

Do not add a network administration endpoint, authorization layer, or placeholder
CA/user/group mutation command. Later tickets will call this boundary only
after their own transaction and atomic-file responsibilities succeed.

**Done when.** Tests establish inactive, active, failure, and durable-ordering
semantics entirely through the public notifier interface and confirm that the
CLI surface remains unchanged.

## 9. systemd example, operator guidance, and epic regression

**Stories.** US-7 and US-9.

**Outcome.** Operators have a concrete `Type=simple` service template and can
run the complete hardened tracer while all Epic 2 scope exclusions remain
enforced.

**Behavioural tests and verification, in order:**

1. A repository-level test verifies that `docs/systemd/ski.service` is
   `Type=simple`, starts the `uv tool install .` executable with `ski serve`,
   reloads with `SIGHUP`, stops with `SIGTERM`, grants only the bind capability
   needed for port 22, and does not define socket activation or `sd_notify`.
2. The example declares its environment handling, working directory, restart
   policy, and startup/shutdown timeouts, and protects the dedicated service
   account and filesystem paths without making future CA state inaccessible.
3. `docs/systemd/INSTALLATION.md` documents installation as the `ski` account
   with `uv tool install .`, template substitution, environment/database
   provisioning, install/enable/start/stop/reload/status commands, journal
   queries using native `SKI_` fields, and the distinction between systemd
   `active` and the application ready event.
4. On Linux where available, `systemd-analyze verify` accepts the substituted
   example unit; other platforms skip only this external verification while
   retaining repository-level assertions.
5. An end-to-end test starts the configured service runtime on unprivileged
   loopback addresses, injects a disposable credential through a real isolated
   forwarded agent, reloads, shuts down, restarts against the same foundational
   database, and repeats successfully.
6. The full suite confirms that no persistent CA, real certificate schema,
   user/password/TOTP model, group principal, KRL, production-host helper,
   socket unit, or additional public CLI command was introduced.

**Implementation boundary.** Add the example and guidance at the story's exact
`docs/systemd/` paths. Treat the unit as a reviewed template which deployment
must adapt; do not install, enable, start, stop, or reload the workstation's
real service during tests or implementation. Keep application-owned sockets,
`CAP_NET_BIND_SERVICE`, `Type=simple`, and native journald logging explicit.

Update README development/smoke-test instructions only as required by the new
mandatory database configuration and runtime behavior. Do not present the
tracer as production-ready.

**Done when.** The standard project checks pass, the example unit has portable
static coverage plus optional Linux verification, the smoke flow still works,
and every Epic 2 acceptance criterion is either exercised by a behavioral test
or covered by operator verification.
