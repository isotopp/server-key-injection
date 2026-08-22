# Offline production-host authorization

## Epic outcome

Make an independently installed, host-local ski-authorize helper allow a
production-style OpenSSH host to accept an ordinary ski certificate only when
the certificate identity and signed group claims satisfy that host's protected
offline policy. A production host needs no route, credential, database, or
runtime dependency belonging to the issuer.

The issuer continues to expose ski ca public-key; deployment tooling or an
operator copies that public key to the target host. This epic supplies
instructions and installable host-authorizer software, but deliberately does
not create a CA-key-distribution mechanism, a remote administration API, or a
configuration-management integration.

## Scope and boundaries

This implements Epic 5 — Offline production-host authorization in the
architecture and refines its host-side authentication and authorization model.

It adds a separately installable host package, a root-protected host policy,
the ski-authorize AuthorizedPrincipalsCommand executable, target-host
installation/configuration documentation, deterministic helper tests, and
manual UTM OpenSSH smoke-test instructions.

It does not distribute a CA public key or mutate a target host remotely; ship
the issuer private CA key, SQLite state, demo identity data, dotenv file, or
issuer executable to a target host; contact the issuer or identity provider at
login; add KRL deployment/revocation, CA rotation, a production identity
provider, account switching, user provisioning, or any temporary/emergency
access mode. KRL adoption and CA rotation remain Epic 6 work.

## Workspace and package boundary

The repository becomes one uv workspace containing two independently
installable projects:

| Project                                         | Distribution and executable   | Installed on      | Must not contain or require                                                                                                       |
|-------------------------------------------------|-------------------------------|-------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| Existing root project                           | ski / ski                     | Issuer only       | Host authorization policy or target-host administration                                                                           |
| New workspace member at packages/ski-authorize/ | ski-authorize / ski-authorize | Target hosts only | Issuer listener, SQLite identity store, dotenv loading, CA private-key handling, issuer network access, or issuer database access |

The host package may use a direct SSH-certificate parsing dependency and the
Python standard library, but it must not import the issuer package as an
implementation shortcut. Its runtime remains intentionally small and has no
network client, listener, daemon, or persistent state.

## CLI surface in this epic

No ski subcommand is added. ski ca public-key remains the issuer-side way to
obtain the public key for external deployment.

ski-authorize is a separate target-host executable, not an alias for ski:

| Command                                                                                                  | Invocation source                      | Purpose                                                                                              |
|----------------------------------------------------------------------------------------------------------|----------------------------------------|------------------------------------------------------------------------------------------------------|
| ski-authorize --config PATH --ca-fingerprint FINGERPRINT TARGET_USER CERTIFICATE_TYPE CERTIFICATE_BASE64 | sshd only                              | Return one permitted principal for the offered certificate, or deny.                                 |
| ski-authorize --check-config --config PATH                                                               | Host operator or deployment validation | Validate the protected local policy without contacting the issuer or producing authorization output. |
| ski-authorize --version                                                                                  | Operator                               | Print the host package version.                                                                      |

The production AuthorizedPrincipalsCommand passes %u, %t, %k, and %F:

~~~sshconfig
AuthorizedPrincipalsCommand /opt/ski-authorize/bin/ski-authorize --config /opt/ski-authorize/config/authorization.toml --ca-fingerprint %F %u %t %k
AuthorizedPrincipalsCommandUser ski-authz
~~~

OpenSSH expands %k to the base64-encoded key or certificate and %t to its
type; the helper reconstructs the OpenSSH public-key form from those two
values before parsing it. %F is the CA-key fingerprint. This corrects the
earlier illustrative %u %k form, which did not supply enough information to
reconstruct the certificate reliably. The relevant token and command-output
contract is defined by the OpenSSH sshd_config(5) manual.

The helper accepts no issuer URL, database, dotenv file, credential, CA
private-key path, policy override, debug mode, account-switch flag, or network
option. Its sshd mode prints exactly one permitted principal followed by a
newline and exits zero, or writes no standard output and exits non-zero.

## User stories

### US-1: Install issuer and authorizer independently from one workspace

As a deployment operator, I can install the issuer project only on the issuer
and the host-authorizer project only on a production host, so that a target
host does not acquire the issuer sensitive code, state, or dependencies.

**Acceptance criteria:**

- The repository is a uv workspace. The current root ski project and
  packages/ski-authorize/ each have their own package metadata, dependency
  closure, console entry point, tests, and independently installable artifact.
- Installing or testing ski-authorize does not import the issuer package or
  require an issuer .env, SQLite database, CA private key, journald binding,
  SSH listener, agent socket, or connection to ssh.example.com.
- The host package has a small explicit dependency set. Certificate parsing is
  a direct declared dependency rather than an accidental import from the
  issuer environment; TOML parsing uses tomllib from Python 3.12.
- The documented target-host installation runs uv tool install . as root from
  the host-project directory, without editable installation, and places all
  uv-managed runtime state below one root-owned /opt/ski-authorize/ tree:
  python/, tools/, bin/, and cache/.
- Installation sets UV_PYTHON_INSTALL_DIR, UV_TOOL_DIR, UV_TOOL_BIN_DIR, and
  UV_CACHE_DIR below that tree. It uses the managed Python installed at
  /opt/ski-authorize/python/ and exposes the fixed absolute command path
  /opt/ski-authorize/bin/ski-authorize to sshd.
- The uv-managed executable link/shim, its resolved tool environment, managed
  Python, and every containing directory are root-owned and not writable by
  group or others. ski-authz has only the read and execute access needed at
  runtime.
- The necessary actions for installation, including the UV environment variables,
  the `uv tool install` call and so on are packaged into a single install.sh in the
  `packages/ski-authorize` directory.
- The host package includes a small sample `authorization.toml` and
  `60-ski-authorize.conf` OpenSSH fragment. The installation documentation and
  script copy them only into their final root-owned locations; tests keep the
  fragment's command argument order synchronized with the helper interface.
- No login-capable application account, systemd unit, listener, scheduler, or
  background process is introduced for the host package. ski-authz is a
  dedicated unprivileged command account with no other role.
- A clean target-host test environment can install and execute only the host
  package. A clean issuer environment can install and execute only ski.

### US-2: Document deliberate public-CA installation on target hosts

As an operator, I have exact documentation for locating the issuer CA public
key and installing it on a target host, so that certificate trust is an
explicit, reviewable deployment decision rather than an implicit application
side effect.

**Acceptance criteria:**

- A new target-host guide in docs/ explains that ski ca public-key runs on the
  issuer and emits only public CA material. It pairs the key with the
  fingerprint displayed by ski ca show for an out-of-band comparison.
- The guide gives commands and ownership/mode requirements to create the
  root-owned /opt/ski-authorize/ installation tree, install the key as
  /opt/ski-authorize/config/user-ca.pub, install
  /opt/ski-authorize/config/authorization.toml, and validate/reload sshd on a
  target host. It distinguishes demo-VM commands from production configuration
  management where useful.
- The only ski-related file outside that tree is the root-owned OpenSSH
  fragment /etc/ssh/sshd_config.d/60-ski-authorize.conf. It contains the
  TrustedUserCAKeys and AuthorizedPrincipalsCommand references into /opt and
  is tested with sshd -t before reload.
- The package supplies the small sample authorization policy and OpenSSH
  fragment installed at those protected locations. The guide identifies them
  as starting points requiring site-specific CA fingerprint and allowed-group
  values, rather than silently installing a usable default policy.
- The guide explicitly says that copying the CA public key, helper package,
  and policy is external deployment work. ski opens no connection to a target
  host and supplies no remote-copy, enrollment, or host-editing command.
  The `packages/ski-authorize/install.sh` script explains the necessary manual steps:
  - What to pick up on the issuer side.
  - Where to put it on the authorizer side, and the requires steps and permissions.
- The guide never instructs operators to copy the issuer private CA key, CA
  database, identity data, .env, user private keys, agent contents, or a KRL
  for this epic. It states that KRL distribution is deferred to Epic 6.
- The guide names the 25-hour default certificate lifetime and its offline
  consequence: a group removal prevents new issuance but an already issued
  certificate may continue to allow new logins until it expires, unless a
  future KRL deployment is used.

### US-3: Configure a hardened OpenSSH target host

As a target-host operator, I can configure OpenSSH to trust exactly the
deployed user CA and invoke the local helper under least privilege, so that
OpenSSH—not the issuer—validates the certificate during a production login.

**Acceptance criteria:**

- The documentation supplies a production sshd_config fragment containing
  PubkeyAuthentication yes, PasswordAuthentication no,
  KbdInteractiveAuthentication no, TrustedUserCAKeys, the compatible Ed25519
  CASignatureAlgorithms setting, and the fixed absolute
  AuthorizedPrincipalsCommand form above.
- OpenSSH 9 or later is required. This epic tests and verifies the complete
  host configuration on a current Rocky Linux 9.x UTM guest. The target-host
  guide documents equivalent Debian and Ubuntu installation/configuration
  steps, but this epic does not claim a tested Debian or Ubuntu host.
- The helper executable link/shim, its resolved interpreter/environment, and
  every containing path below /opt/ski-authorize are root-owned and not
  writable by group or others. The policy and CA public-key files are regular,
  non-symlink root-owned files which are not writable by group or others.
- sshd runs the helper as the dedicated ski-authz account, which can read only
  the public host configuration it needs and has no issuer credential,
  database access, shell login, or network dependency.
- The host normal account lifecycle is external. OpenSSH must already regard
  %u as a valid local account; this epic neither creates accounts nor maps a
  certificate user to a different Unix account.
- Agent, TCP, X11, and port forwarding remain disabled by the production host
  baseline except where the host independently reviewed Match policy allows
  them. This epic adds no certificate critical option or forwarding override.
- KRL configuration is commented as a future optional RevokedKeys line only;
  it is not enabled, generated, or distributed by this epic.

### US-4: Declare one strict, local host group policy

As a target-host operator, I can declare the groups permitted to log in to this
host in a small protected TOML file, so that each host independently limits the
scope of the issuer signed group claims.

**Acceptance criteria:**

- /opt/ski-authorize/config/authorization.toml has one strict schema:

  ~~~toml
  [ssh]
  trusted_ca_fingerprint = "SHA256:..."
  allowed_groups = ["group:platform-ops", "group:database-oncall"]
  allow_self_login_only = true
  ~~~

- trusted_ca_fingerprint is the exact public fingerprint reviewed during CA
  installation. allowed_groups may be empty to deny all certificate logins;
  otherwise every entry is a unique canonical group:<group-name> principal.
- allow_self_login_only is required and must be exactly true. Missing, false,
  malformed, duplicated, unknown, or extra configuration fields fail closed.
  There is no per-user allowlist, wildcard, group hierarchy, implicit default,
  account-switch, service-account, or root policy in this epic.
- The helper reads the configuration on each invocation without following a
  final-component symlink, and verifies it is a regular root-owned file with
  no group/other write permission before parsing. A missing, unreadable, or
  malformed policy produces no principal and a non-zero status.
- ski-authorize --check-config uses exactly the same validation path as sshd
  mode and prints only a safe success/failure summary. It does not contact the
  issuer, load a CA private key, or authorize a user.

### US-5: Make one offline, certificate-bound authorization decision

As a certificate-bearing user, I can log in only to my own existing local
account when my certificate contains a group the host permits, so that neither
a certificate claim nor local policy alone can grant access.

**Acceptance criteria:**

- In sshd mode, the helper uses CERTIFICATE_TYPE and CERTIFICATE_BASE64 only to
  reconstruct and parse the offered public key. It requires an
  ssh-ed25519-cert-v01@openssh.com user certificate; malformed encoding, an
  ordinary key, a host certificate, another algorithm, or unsupported
  certificate data is denied.
- The helper requires the --ca-fingerprint value supplied by OpenSSH to exactly
  equal the policy trusted_ca_fingerprint. OpenSSH TrustedUserCAKeys remains
  responsible for cryptographic CA signature verification; the helper does not
  introduce a second online trust lookup.
- It requires a currently time-valid certificate, a canonical key_id, and the
  exact target-account binding TARGET_USER == key_id. It also requires
  TARGET_USER to be present as the certificate canonical identity principal.
- Certificate principals are accepted only in the known grammar: exactly the
  canonical identity principal plus distinct canonical group:<group-name>
  principals. Missing identity, missing groups, duplicate claims, malformed
  claims, or unrecognised extra claims deny access.
- The helper intersects certificate group principals with local allowed_groups.
  A non-empty intersection permits access; it writes the lexicographically
  first matching group principal, which is known to be in the certificate, to
  standard output. Every denial, parsing failure, policy failure, or ambiguous
  result writes no standard output and exits non-zero.
- The helper makes no network call and reads no issuer database, cache, user
  directory, environment file, CA private key, or runtime state. It does not
  log raw certificates, principals beyond the safe final decision, identity
  secrets, or policy contents.

### US-6: Provide unit evidence and manual OpenSSH smoke tests

As an operator or security reviewer, I can follow repeatable smoke-test
instructions against a UTM production-style host and inspect deterministic
helper tests, so that the host-side access-control contract is verifiable
without adding VM automation or a CI dependency.

**Acceptance criteria:**

- Unit and command-level tests cover configuration validation, policy file
  safety, valid certificate parsing, identity/account binding, canonical
  principal grammar, group intersection, deterministic principal output, and
  no-output non-zero denial behavior.
- The target-host guide contains a manual UTM smoke test which installs only
  the host-authorizer artifact, local CA public key, policy, and sshd_config on
  a production-style test host. It explicitly confirms that the host has no
  issuer process, SQLite state, issuer credential, or issuer network route.
- The smoke-test instructions demonstrate an accepted unexpired issuer
  certificate for its matching local account and allowed group, then denials
  for a certificate signed by another CA, wrong target account, missing or
  malformed identity/group principals, disallowed group, malformed policy,
  CA-fingerprint mismatch, and unavailable helper/configuration. They identify
  expiry/not-yet-valid certificate checks as an OpenSSH time-validity case.
- The instructions also demonstrate that an ordinary public key and a
  certificate with an unexpected key or CA algorithm are not admitted through
  the helper path, and that an empty allowed_groups policy denies all.
- VM provisioning, setup, and smoke-test execution are deliberately manual.
  This epic adds no UTM automation, remote test runner, pytest marker, CI job,
  VM image builder, or test-time host mutation mechanism.
- Smoke-test diagnostics and helper output must contain no private key, agent
  payload, password, TOTP value/secret, issuer database data, or raw complete
  certificate input. The normal project formatter, linter, type checker, and
  helper/unit test suite remain green.

### US-7: Preserve the offline authorization boundary

As a security reviewer, I can verify that Epic 5 enables only normal,
certificate-backed self-login under local group policy, so that it does not
quietly create a network dependency or a broader privileged-access path.

**Acceptance criteria:**

- Target-host documentation makes the issuer/production firewall boundary
  explicit: issuance happens from the office network; production authorizes
  locally and never initiates a connection into that network.
- The deployed host package contains no issuer endpoint, token, credential,
  dotenv lookup, database path, remote policy lookup, telemetry export, or
  configuration-management client. Failure to read local policy or parse local
  certificate input fails closed.
- No ski CLI command, issuer schema table, issuer listener endpoint, or
  target-host mutation protocol is added for host enrollment, policy editing,
  CA copying, KRL copying, revocation, rotation, account creation, account
  switching, or emergency access.
- The documentation and package metadata clearly distinguish the issuer
  installation from the target-host authorizer installation and identify the
  root-owned files that OpenSSH trusts.
- The next security review is scheduled after Epic 6, which introduces KRL
  distribution and CA rotation. This epic adds no separate post-implementation
  security-review gate.

## Decisions made during story refinement

- The issuer and production host are two separately installable uv projects in
  a single workspace, rather than two repositories or one deploy-everywhere
  package.
- The issuer has no CA-public-key distribution feature. Operators use ski ca
  public-key and normal reviewed deployment/configuration-management paths to
  install public material on a host.
- All host-authorizer runtime material is contained below the root-owned
  /opt/ski-authorize/ tree: the uv-managed Python, tool environment,
  executable link/shim, installation cache, public CA key, and local policy.
  The only external integration file is the root-owned OpenSSH configuration
  fragment in /etc/ssh/sshd_config.d/.
- ski-authorize is the only host-side executable in this epic. It is an
  AuthorizedPrincipalsCommand, not a daemon, SSH server, issuer client, or ski
  subcommand.
- The target-host command receives %u, %t, %k, and %F; %t is needed to parse
  the base64 certificate supplied by %k, and %F binds the helper local policy
  to the CA configured in sshd.
- The host package includes a deliberately incomplete sample policy and OpenSSH
  fragment. After installation their final locations are root-owned; tests
  protect their command contract from drifting from the helper interface.
- OpenSSH 9 is the required target-host baseline. Epic 5 verifies it on a
  current Rocky Linux 9.x UTM guest and documents, but does not test, Debian
  and Ubuntu target-host installation.
- `trusted_ca_fingerprint` is retained in the local policy and compared with
  the `%F` value supplied by OpenSSH. It is a fail-closed pin against an
  accidental broadening of `TrustedUserCAKeys`; CA-rotation overlap belongs to
  Epic 6.
- Ordinary access is self-login only. A certificate must bind its canonical
  key_id and identity principal to the requested local account, then contain
  at least one locally allowed signed group principal.
- The production host may be isolated from the issuer. It relies on its local
  CA public key, static policy, helper, and normal time synchronization. The
  25-hour certificate lifetime is the accepted maximum group-removal gap until
  a later KRL rollout.
