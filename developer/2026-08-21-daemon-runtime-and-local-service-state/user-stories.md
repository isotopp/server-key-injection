# Daemon runtime and local service state

## Epic outcome

Turn the test issuer into a predictable, single-instance foreground service
which can be supervised by systemd. The service loads and validates one
configuration snapshot, binds its requested listeners as a unit, opens local
SQLite state, emits structured operational events, and responds safely to
shutdown and reload signals.

At the end of this epic, operators can start, stop, and reload the tracer
without corrupting its local state or allowing a request to observe partially
reloaded configuration. The certificate remains the harmless dummy credential
from Epic 1.

## Scope and boundaries

This epic implements only the runtime described in
[Epic 2 — Daemon runtime and local service state](../architecture.md#epic-2--daemon-runtime-and-local-service-state)
and the corresponding
[deployment and operational model](../architecture.md#deployment-and-operational-model).

It includes foundational SQLite lifecycle and transaction behaviour, but not
the CA, certificate, identity, group, audit, revocation, or KRL schemas owned by
later epics. It does not add password/TOTP authentication, trusted
certificates, production-host authorization, or a production identity store.

## User stories

### US-1: Start from one validated configuration snapshot

As an operator, I can start `ski serve` using the documented configuration
search order and service options, so that the daemon either starts with one
complete, valid configuration or fails before accepting connections.

**Acceptance criteria:**

- Startup searches `./.env`, `$HOME/.ski.env`, then `/home/ski/etc/env`, stops at the
  first existing file, and gives already exported process environment values
  precedence.
- Configuration is parsed into an immutable application-level snapshot rather
  than read piecemeal from `os.environ` while requests are running.
- The configured SQLite path is required and validated before listeners are
  made available. The parent directory must already exist and be writable by
  the service account.
- Malformed, missing, contradictory, or unsafe required values cause a clear
  startup failure without opening a listener or leaving a partial state file.
- Logs and errors may identify a configuration key or path, but never disclose
  secret values.

### US-2: Bind the requested service addresses atomically

As an operator, I can bind the issuer to one address or to the wildcard service
address, so that its network exposure matches the CLI contract.

**Acceptance criteria:**

- `ski serve --bind IP --port PORT` keeps the public option names and defaults
  documented in the architecture: `--bind *` and `--port 22`.
- `ski` creates and owns every listening socket. It does not use systemd socket
  activation or consume inherited listener file descriptors.
- Port values outside `1..65535` and invalid bind values are rejected before
  service startup. Internal test APIs may still use an ephemeral port without
  widening the public CLI contract.
- `--bind *` opens both `0.0.0.0` and `::`; it is not delegated to
  platform-dependent wildcard resolution.
- If either wildcard listener cannot be opened, every listener opened during
  that attempt is closed and startup fails.
- A specific IPv4 or IPv6 address opens only the requested listener.
- The ready event reports all effective bound addresses only after local state
  and every required listener are ready.

### US-3: Own local SQLite state safely

As an operator, I can run one issuer against its configured local SQLite
database, so that service state survives restarts and concurrent administrative
writes do not corrupt it.

**Acceptance criteria:**

- The state database is a local SQLite file selected by `SKI_CA_DATABASE`; it
  is not selectable with a command-line option.
- First startup may create the database and foundational schema without
  creating CA material. The later `ski ca init` command initializes CA state,
  not the SQLite container itself.
- Schema versioning is explicit, repeatable, transactional, and refuses a
  database created by a newer unsupported application version.
- SQLite foreign keys are enabled, a finite busy timeout is configured, and
  writes use short explicit transactions which commit or roll back as a unit.
- The daemon holds a non-destructive advisory lock associated with this state
  database for its lifetime. A second daemon targeting the same database fails
  before binding, even if it requests a different address or port.
- Administrative processes can still open the database and perform short
  transactions while the daemon holds its service-instance lock.
- Startup closes the database and releases its instance lock after any later
  initialization or bind failure.

### US-4: Emit structured service logs

As an operator, I can inspect the daemon through journald, so that startup,
reload, shutdown, and request outcomes are observable without exposing
sensitive material.

**Acceptance criteria:**

- The foreground daemon writes structured records through journald's native API
  using the accepted `systemd-python` dependency and does not manage its own
  log files.
- Records use standard journal fields including `MESSAGE`, `PRIORITY`, and
  `SYSLOG_IDENTIFIER`, plus stable application fields prefixed with `SKI_` for
  event name and request ID when a request exists. systemd supplies trusted
  process and unit metadata.
- Application fields are native, directly queryable journal fields; structured
  data is not serialized as JSON inside `MESSAGE`.
- Startup, ready, reload accepted/rejected, shutdown requested/completed,
  listener failure, database failure, and tracer request outcome are distinct
  events.
- Passwords, TOTP secrets, private keys, agent protocol payloads, complete
  environment values, and exception representations which may contain those
  values are excluded.
- Logging is behind an application interface. Automated tests use an in-memory
  sink to capture and assert complete records without requiring systemd or a
  running journal.

### US-5: Shut down gracefully on service signals

As an operator, I can stop the service with systemd or interrupt it during
development, so that it stops accepting work and releases resources in a
bounded time.

**Acceptance criteria:**

- `SIGTERM` and `SIGINT` enter the same idempotent shutdown path.
- Shutdown first closes all listeners, then allows in-flight requests a bounded
  grace period, cancels any remainder, closes SQLite connections, releases the
  instance lock, and exits.
- A second shutdown signal does not start a competing cleanup path or produce
  a traceback.
- Shutdown emits requested and completed events; cancellation does not log
  credential or agent data.
- Tests exercise shutdown with no requests, a completed request, and a request
  which exceeds the grace period.

### US-6: Reload configuration without partial activation

As an operator, I can send `SIGHUP` to a running issuer, so that reloadable
configuration and file-backed state change together or the previous working
snapshot remains active.

**Acceptance criteria:**

- `SIGHUP` starts one serialized reload; repeated signals are coalesced or
  processed sequentially rather than concurrently.
- Reload repeats the documented environment-file search using the original
  exported-process environment as its precedence baseline. Values loaded by a
  previous dotenv read do not masquerade as exported values.
- The candidate configuration and file-backed state are fully loaded and
  validated before one atomic snapshot replacement.
- Existing requests retain their original snapshot; requests beginning after a
  successful swap receive the new snapshot.
- Listener address, listener port, and database path are startup-only settings.
  A reload which changes one is rejected with a restart-required event and
  leaves the complete previous snapshot active.
- Any invalid candidate or reload failure leaves listeners, database state,
  and the previous configuration active.
- Reload never interrupts the process or emits a traceback into the user's SSH
  session.

### US-7: Run under systemd without daemon-specific lifecycle commands

As an operator, I can install a systemd unit for `ski`, so that the operating
system owns startup, reload, logging, privilege, and termination.

**Acceptance criteria:**

- The repository supplies an example unit at `./docs/systemd/ski.service`
  and installation guidance using a dedicated `ski` account and a pre-built uv
  environment in `./docs/systemd/INSTALLATION.md`.
  It assumes the binaries have been installed with `uv tool install .` in the `ski` account.
- `ExecStart` invokes the environment's installed `ski serve` executable and
  does not resolve or install dependencies during startup.
- The unit sends `SIGHUP` for reload and `SIGTERM` for stop, uses
  `CAP_NET_BIND_SERVICE` when binding port 22, and permits the daemon to submit
  records through the native journal API.
- The example declares its environment-file handling, working directory,
  restart policy, startup and shutdown timeouts, and `Type=simple`.
- The deployment contains no `ski.socket` unit. The service receives
  `CAP_NET_BIND_SERVICE` when it must bind port 22 itself.
- systemd creates and protects any runtime directory needed for the service;
  persistent database and future key paths remain separately provisioned.
- After configuration, SQLite state, the instance lock, and listeners are
  ready, the service emits a structured ready event to the journal. It does not
  call `sd_notify`.
- The documentation states that `Type=simple` makes systemd consider the unit
  started when the process has executed; an `active` unit is not itself proof
  that application initialization or listener binding has completed.
- The documentation gives operators start, stop, reload, status, and journal
  commands without introducing equivalent `ski` subcommands.
- The example is a reviewed template, not an automatically installed or
  enabled unit; deployment tooling must substitute the actual virtual
  environment, user, group, and filesystem paths.

### US-8: Notify an active daemon after future mutations

As a future administrative-command implementer, I have one notification
boundary to call after a durable mutation, so that later commands can request a
daemon reload without duplicating systemd integration.

**Acceptance criteria:**

- The notification boundary is callable only after a database transaction has
  committed and any application-owned file has been atomically replaced.
- It asks the local service manager to reload the configured `ski` unit when
  active; it does not define a network administration endpoint or second
  authorization mechanism.
- A stopped service is a successful no-op because the next startup reads the
  durable state.
- A committed mutation remains committed if notification fails; the caller
  receives a clear operational warning and non-success result suitable for
  retrying notification without repeating the mutation.
- Tests use an injected service-manager adapter and never signal or reload the
  developer's real system service.
- This epic implements and tests the reusable boundary but adds no mutating CA,
  user, or group command merely to exercise it.

### US-9: Preserve the harmless tracer boundary

As a security reviewer, I can verify that runtime hardening has not turned the
Epic 1 tracer into an access credential or authentication service.

**Acceptance criteria:**

- The issuer still uses the disposable in-memory test CA and one-hour `test-`
  credentials from Epic 1.
- No persistent CA key, real certificate record, user/password/TOTP data,
  signed group claim, KRL, or production-host helper is introduced.
- SQLite contains only foundational service/schema state in this epic.
- A restart invalidates the disposable CA just as it did in Epic 1.

## CLI surface decisions

Epic 2 implements or refines only this public command:

| Command     | Options                                                 | Epic 2 responsibility                                                                                                                            |
|-------------|---------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| `ski serve` | `--bind IP` (default `*`); `--port PORT` (default `22`) | Validate startup options, bind one specific address or both wildcard families atomically, run in the foreground, and respond to service signals. |

The existing global `--help`, command help, and `--version` remain supported.
No additional public command or option is required for this epic:

- There is no `ski stop`, `ski reload`, or `ski status`; operators use
  `systemctl stop`, `systemctl reload`, and `systemctl status`.
- There is no `--daemonize`, `--pid-file`, or log-file option; systemd owns the
  process and logging lifecycle.
- There is no `--config` or `--database` option; configuration selection and
  `SKI_CA_DATABASE` remain part of the deployment contract.
- There is no mutation command in this epic. The internal notification
  boundary is consumed when later `ski ca`, `ski user`, and `ski group`
  commands are implemented.

## Decisions made during story refinement

- The service-instance lock is scoped to the configured database, preventing
  two issuers from using one state store while still permitting independent
  development instances with different databases.
- SQLite foundation creation is separate from CA initialization. This keeps
  Epic 2 runnable while preserving `ski ca init` for the persistent-CA epic.
- Bind address, port, and database path are startup-only. SIGHUP cannot safely
  move live listeners or state ownership; changing them requires a restart.
- `ski` owns its listening sockets; systemd socket activation is not used.
- The example service uses `Type=simple`. Readiness is a structured log event,
  not a systemd readiness notification, so unit activation and application
  readiness are intentionally distinct.
- Operational logging uses native journald fields through `systemd-python`, not
  JSON Lines. The logging interface remains replaceable so tests and
  non-systemd development runs do not require a journal daemon.
- Reload uses a two-phase validate-and-swap model. It never incrementally
  mutates the configuration visible to requests.
- Notification failure after a committed future mutation is an operational
  failure, not grounds to roll back or repeat the already durable mutation.
