# Offline production-host authorization — US-1 tickets

## Implementation rules

Implement these tickets in order. For every ticket, begin with one public
behavioural test, make only that test pass, and then add the next behaviour.
Do not write a ticket's entire test suite before its first green slice. Refactor
only while the tests are green.

Host-package tests must exercise the separately installed `ski-authorize`
artifact, its console command, and real package metadata where practical. They
must not import `ski` to generate or inspect a result. Use temporary
directories and subprocesses for installation/layout checks; substitute only
root-only operations and the final UTM host. Keep a future host package free of
the issuer's SQLite state, dotenv, journald, listener, agent, and network
dependencies.

Run `uv run ruff format`, `uv run ruff check --fix`, `uv run ty check`, and
`uv run pytest` before completing each ticket. Commit each completed ticket
using the git-commit skill before starting the next one.

## 1.1 Create the workspace and independently buildable host package

**Stories.** US-1.

**Outcome.** The repository is a uv workspace with the existing issuer as its
root project and a new, independently buildable `packages/ski-authorize/`
project. The new package has no runtime path to issuer code.

**Behavioural tests, in order:**

1. From the host-project directory, a clean package build produces a
   `ski-authorize` distribution whose metadata identifies only the host package
   and whose wheel contains its own `ski_authorize` source.
2. Installing that built artifact into an isolated environment exposes a
   `ski-authorize --version` command and does not install or import `ski`.
3. The root issuer project remains buildable and its `ski --version` command
   remains unchanged after workspace metadata is introduced.

**Implementation boundary.** Add uv workspace metadata at the repository root
and create `packages/ski-authorize/` with independent `pyproject.toml`,
`src/ski_authorize/`, tests, readme/package data declarations, and a
`ski-authorize` console entry point. Require Python 3.12. Make the initial
command expose only `--version`; do not add issuer functionality or an
authorization implementation yet. Declare a direct SSH-certificate parsing
dependency only in the host project when its first public parser is introduced,
not speculatively in this ticket.

**Done when.** Both projects build independently and an isolated host-package
installation proves the `ski-authorize` command has no issuer import or runtime
dependency.

## 1.2 Establish the host package's intentionally narrow public surface

**Stories.** US-1 and CLI surface.

**Outcome.** The installed host executable has a stable, separate command
shape before the authorization behaviour is added, without exposing accidental
issuer or administration options.

**Behavioural tests, in order:**

1. `ski-authorize --help` identifies it as a target-host authorization helper
   and lists only `--version`, `--config`, `--check-config`, and the future
   sshd positional invocation shape.
2. Supplying an issuer URL, database path, dotenv path, CA private-key path,
   policy override, network option, account-switch flag, or unknown option is
   rejected without output that discloses configuration state.
3. Invoking the unfinished sshd mode or `--check-config` before the later
   tickets implements them fails closed: non-zero status and no principal on
   standard output.

**Implementation boundary.** Keep parsing and process entry-point code inside
the host package. Define the stable command argument order now as
`--config PATH --ca-fingerprint FINGERPRINT TARGET_USER CERTIFICATE_TYPE
CERTIFICATE_BASE64`; reserve `--check-config --config PATH` for the policy
ticket. Do not make it a `ski` subcommand, load dotenv, or add diagnostics that
could become an sshd authorization response.

**Done when.** Help and rejection tests establish a small, issuer-independent
public command contract suitable for the packaged OpenSSH sample.

## 1.3 Package safe, deliberately incomplete host configuration samples

**Stories.** US-1, US-2, and US-3.

**Outcome.** The host artifact ships a reviewable sample
`authorization.toml` and `60-ski-authorize.conf` that exactly match the public
helper contract but cannot accidentally enable access unchanged.

**Behavioural tests, in order:**

1. A built wheel contains both declared sample files at stable package-relative
   paths.
2. The sample TOML contains an explicit CA-fingerprint placeholder and an
   empty allowed-group list, so it cannot become a usable allow policy without
   an operator's deliberate edit; later policy tests validate the same file
   shape after replacement.
3. The sample OpenSSH fragment uses only absolute `/opt/ski-authorize/...`
   paths and invokes the helper as
   `--config ... --ca-fingerprint %F %u %t %k` in that exact order, with
   `AuthorizedPrincipalsCommandUser ski-authz`.
4. The fragment enables the intended certificate authentication baseline and
   leaves `RevokedKeys` as a clearly marked future Epic 6 setting rather than
   enabling an absent KRL.

**Implementation boundary.** Add minimal sample assets as package data, with
comments explaining which values must be replaced and why they are root-owned
only after deployment. Do not add a writable default, CA key, KRL, or host
mutation feature. Keep the fragment test structural and owned by the host
package so command-interface drift is caught before installation work.

**Done when.** The independently built package carries safe samples whose
helper invocation, paths, and fail-closed defaults are test-protected.

## 1.4 Provide the root-run host installation script and protected layout

**Stories.** US-1 and US-2.

**Outcome.** A root-run `packages/ski-authorize/install.sh` installs the host
artifact using uv's managed Python/tool locations below `/opt/ski-authorize`,
creates the dedicated command account, and places the supplied samples only in
their protected final locations.

**Behavioural tests, in order:**

1. Script usage or a non-root invocation fails before creating files or
   invoking uv.
2. A structural script test verifies the exact uv environment variables and
   commands for managed Python 3.12 plus a non-editable `uv tool install .`,
   and verifies the expected fixed `bin/ski-authorize` path without creating a
   test-only installation prefix.
3. The installation plan creates only the declared `/opt/ski-authorize`
   subtrees (`python`, `tools`, `bin`, `cache`, `config`) plus the sole
   external `/etc/ssh/sshd_config.d/60-ski-authorize.conf` integration file.
4. A completed installation leaves all executable/interpreter/tool/config
   paths root-owned and non-group/world-writable; `ski-authz` receives only the
   read/execute access necessary to invoke the helper and read public host
   configuration.
5. Re-running the script is an intentional upgrade/reinstall operation: it
   never follows a target symlink, preserves an operator-modified policy unless
   explicitly requested by a documented safe option, and never starts a daemon
   or listener.

**Implementation boundary.** Implement a short auditable shell script, not a
new Python installer or service. Use fixed defaults required by the story:
`UV_PYTHON_INSTALL_DIR=/opt/ski-authorize/python`,
`UV_TOOL_DIR=/opt/ski-authorize/tools`,
`UV_TOOL_BIN_DIR=/opt/ski-authorize/bin`, and
`UV_CACHE_DIR=/opt/ski-authorize/cache`. Create/configure the non-login
`ski-authz` account through native host commands documented for the supported
Rocky target. Keep privileged mutations constrained to the final paths; do not
copy issuer files or configure systemd.

**Done when.** Script tests demonstrate the exact uv layout, fail-closed
privilege checks, protected paths, idempotent policy handling, and absence of
issuer/runtime side effects.

## 1.5 Prove clean issuer/host installation separation

**Stories.** US-1 and US-7.

**Outcome.** Reproducible package-level evidence shows that a target host can
install and run only the authorizer, while the issuer installation remains
unaffected by the workspace split.

**Behavioural tests, in order:**

1. A fresh isolated environment installing only the built host artifact can
   execute `ski-authorize --version` and does not contain the issuer package or
   its issuer-only dependencies.
2. The same environment has no dotenv lookup, database opening, listener,
   network client, journald binding, or agent-socket side effect when invoking
   `--version`, help, or a denied unfinished command.
3. A clean issuer-only environment still runs the existing issuer CLI and test
   suite without requiring the host package.

**Implementation boundary.** Add black-box installation checks using real
temporary environments/artifacts, without importing package internals to prove
absence. Keep unsupported dependency leakage as a failing regression. Do not
add a UTM runner, remote test, or CI matrix; the later manual Rocky UTM smoke
test belongs in `tickets-2plus.md`.

**Done when.** Public artifact tests prove the intended one-workspace,
two-installation boundary.
