# Epic 8 implementation tickets

These tickets implement the documentation-only Epic 8 in order. The ticket
step changes Markdown files under `docs/` only. `README.md` and the epic
user-story file were committed before this ticket step and are not reopened by
these tickets.

Epic 6 is a prerequisite for documenting its final KRL and CA-rotation command
surface. Until Epic 6 is complete, documentation must describe the current
implemented command surface and clearly label KRL/rotation behavior as pending;
it must never invent commands or claim an unimplemented operational feature.

## DOC-1 — Establish the documentation map and source-of-truth boundaries

**Stories:** US-1, US-4

**Depends on:** none

**Outcome:** An operator can find the right guide, and every guide identifies
which responsibilities are supplied by `ski` versus owned by an installer.

**Implementation:**

- Inventory the existing `docs/INSTALLATION.md`, `docs/OPERATION.md`,
  `docs/TARGET-HOST.md`, and `docs/systemd/INSTALLATION.md` guidance against
  `developer/architecture.md`, the current CLI, and the current package
  boundaries.
- Add or revise a small `docs/` index/navigation section if needed; do not
  duplicate command procedures merely to create an index.
- Define consistent terminology for issuer, SQLite demo identity store,
  `ski-authorize`, target host, CA public key, KRL, and installer-owned work.
- Mark Epic 6-dependent material as pending until its implementation exists.

**Acceptance checks:**

- Every guide has a clear audience and links to the next relevant guide.
- No guide promises LDAP/AD/Okta integration, host enrollment, monitoring,
  SELinux policy, configuration-management clients, or other installer-owned
  controls as project features.
- Paths, package names, command names, and the offline trust boundary agree
  with the architecture and source.

**Validation:** `git diff --check`; manual link/path/terminology review across
all Markdown files in `docs/`.

## DOC-2 — Complete issuer lifecycle, recovery, and operations guidance

**Stories:** US-1

**Depends on:** DOC-1; Epic 6 before final KRL/rotation wording

**Outcome:** An issuer operator can install, operate, inspect, back up, and
recover the SQLite proof of concept without confusing documentation with an
automated operational control.

**Implementation:**

- Reconcile `docs/INSTALLATION.md`, `docs/OPERATION.md`, and
  `docs/systemd/INSTALLATION.md` with the implemented issuer CLI and systemd
  behavior.
- Document the protected recovery set: SQLite database, CA private/public key,
  KRL when implemented, and sensitive password/TOTP data in the demo store.
- Document safe backup, restore, validation, readiness, NTP, journald, and
  service lifecycle responsibilities as operator procedures only.
- After Epic 6, add the exact implemented CA-log, revocation/KRL, and CA
  rotation procedures; before then, retain explicit pending/out-of-scope text.
- State that monitoring, alerting, retention, incident response, break-glass
  process, and backup infrastructure are installer-owned.

**Acceptance checks:**

- Every command shown exists in the current CLI at the time of implementation,
  or is explicitly marked as an Epic 6 prerequisite rather than runnable now.
- Recovery instructions preserve ownership, permissions, and the relationship
  between the database, CA files, and materialized KRL.
- No procedure asks an operator to place secrets in Git, unit files, logs, or
  user home directories.

**Validation:** `git diff --check`; compare every command against `uv run ski --help`
and the relevant subcommand help; perform a manual documentation
review of the recovery and systemd sequences.

## DOC-3 — Finish target-host offline authorization and installer handoff

**Stories:** US-2, US-4

**Depends on:** DOC-1; Epic 6 before final KRL adoption wording

**Outcome:** A target-host operator can install and maintain the host helper and
local trust material while understanding that production controls remain
organization-owned.

**Implementation:**

- Reconcile `docs/TARGET-HOST.md` with the package installer, sample policy,
  sample `sshd_config` fragment, OpenSSH 9 requirement, and Rocky UTM smoke
  result.
- Document public-only CA hand-off, exact root-owned `/opt/ski-authorize`
  paths, `ski-authz`, local Unix account requirements, and offline login.
- Document optional KRL pickup and `RevokedKeys` adoption only after Epic 6
  supplies the actual materialization/reconciliation behavior; otherwise keep
  the future boundary explicit.
- Record the SELinux finding accurately: the installer must provide an
  organization-owned labeling/policy solution and must not authorize broad
  `ldconfig` execution or recommend `audit2allow` as a shortcut.
- State that configuration management, firewall/routing, host account
  lifecycle, Debian/Ubuntu validation, monitoring, and production assurance
  are outside the project boundary.

**Acceptance checks:**

- The guide never directs copying issuer private keys, SQLite state, dotenv
  files, user keys, agent contents, or credentials to a host.
- The exact helper invocation remains `%F %u %t %k`, and the documented
  forwarding, CA, policy, ownership, and reload contracts match the package
  assets.
- The KRL section cannot be mistaken for a network dependency or a mandatory
  host feature.
- The manual Rocky 9.x UTM result and Debian/Ubuntu documentation-only status
  are preserved.

**Validation:** `git diff --check`; compare the guide with package samples and
`packages/ski-authorize` help; manually review the SELinux and KRL wording.

## DOC-4 — Document the end-user certificate and agent experience

**Stories:** US-3

**Depends on:** DOC-1

**Outcome:** A user can understand how to obtain, inspect, renew, and safely
use an agent-held certificate without being told to manage a private key file.

**Implementation:**

- Add or reconcile the end-user section in `docs/OPERATION.md` with the actual
  password/TOTP prompt, agent-forwarding requirement, key-loaded output, and
  `ssh-add -l` behavior.
- Explain the relationship between the private key and `ED25519-CERT` entry,
  the 25-hour default lifetime, renewal, group snapshots, and optional KRL
  early revocation.
- Explain the safe agent-forwarding boundary and failure cases without
  promising automatic renewal, a client daemon, or persistent user key files.
- Link the issuer flow to the target-host guide while keeping issuer login and
  production-host login visibly separate.

**Acceptance checks:**

- Commands and output examples match the current implementation and do not
  expose passwords, TOTP secrets, private keys, or agent payloads.
- The text states that a compromised workstation or forwarded agent remains a
  serious risk.
- Group removal and certificate expiry are described with the correct offline
  timing semantics.

**Validation:** `git diff --check`; manually execute or compare the documented
  smoke-test flow with the existing README and `docs/OPERATION.md` examples.

## DOC-5 — Perform the final documentation consistency and handoff review

**Stories:** US-4

**Depends on:** DOC-2, DOC-3, DOC-4, and Epic 6 for final lifecycle claims

**Outcome:** The documentation set is internally consistent and ready to hand
off to an installing organization.

**Implementation:**

- Review every Markdown file under `docs/` against the architecture, current
  CLI help, package samples, and implemented Epic 6 behavior.
- Remove stale “not implemented” statements for delivered features and retain
  explicit boundaries for cancelled Epic 7 work and installer-owned controls.
- Check all relative links, paths, service names, command examples, version
  requirements, certificate lifetime statements, and security caveats.
- Ensure the docs do not claim that the project supplies identity integration,
  configuration management, monitoring, alerting, SELinux policy, or incident
  response.

**Acceptance checks:**

- `docs/` gives a coherent installation-to-operation-to-target-host handoff.
- No documentation contradicts the README, architecture, package assets, or
  actual CLI surface.
- The final diff contains only documentation changes under `docs/` for this
  epic.

**Validation:** `git diff --check`; manually follow links and command snippets;
record unresolved installer-specific controls as handoff notes rather than
creating implementation work in this repository.
