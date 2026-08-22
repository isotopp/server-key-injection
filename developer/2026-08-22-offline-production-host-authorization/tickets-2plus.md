# Offline production-host authorization — US-2 through US-7 tickets

## Implementation rules

Implement these tickets after every ticket in `tickets-1.md` is complete and
committed. Within each ticket, use vertical TDD slices: one externally visible
behavioural test, the smallest implementation to pass it, then the next
behaviour. Refactor only with green tests.

Exercise the installed `ski-authorize` command, real temporary files, real
AsyncSSH/OpenSSH-compatible certificate objects, and subprocess boundaries
where practical. Do not import `ski`, query issuer SQLite state, mock host
authorization internals, or rely on a networked issuer. Substitute only time
and root/UTM-specific operations. Assertions must verify a decision, CLI
status, stdout contract, installed artifact, or documentation contract—not
private implementation calls.

Run `uv run ruff format`, `uv run ruff check --fix`, `uv run ty check`, and
`uv run pytest` before completing each ticket. Commit each completed ticket
using the git-commit skill before beginning the next one.

## 2.1 Implement strict protected local-policy validation

**Stories.** US-4.

**Outcome.** `ski-authorize --check-config --config PATH` validates one
protected, exact host-policy schema without authorizing a user or consulting
the issuer.

**Behavioural tests, in order:**

1. A root-owned regular temporary policy containing an exact SHA256 CA
   fingerprint, distinct canonical `group:` values, and
   `allow_self_login_only = true` makes `--check-config` emit a safe success
   summary and exit zero.
2. An empty `allowed_groups` list remains valid and is reported without
   pretending it permits access.
3. Missing fields, false self-login, non-string fingerprint, malformed or
   duplicate group claims, empty group name, unknown/extra fields, TOML parse
   failure, and duplicate TOML keys fail non-zero with no authorization
   principal output.
4. Missing, unreadable, symlink, non-regular, wrong-owner, or group/other
   writable policy files fail closed before TOML is trusted.

**Implementation boundary.** Introduce a small immutable host-policy value
object plus a no-follow secure-file reader in `ski_authorize`. Require the
effective owner to be root and deny group/other writable policy files. Reuse
this exact validation path in later sshd mode. Do not parse certificates,
perform CA cryptography, read issuer configuration, or add policy overrides.

**Done when.** The public check command proves strict schema and local file
safety with safe, non-authorizing output.

## 2.2 Parse and validate the offered certificate contract

**Stories.** US-5.

**Outcome.** The host package can reconstruct the OpenSSH public-key form
from `%t` and `%k`, then extract only the certificate attributes needed for a
local authorization decision.

**Behavioural tests, in order:**

1. A valid generated Ed25519 user certificate supplied as its exact type and
base64 body is accepted by the public host parser and exposes only safe
decision attributes: key ID, principals, validity interval, CA fingerprint,
and key/certificate algorithm.
2. A malformed base64 body, mismatched type/body, ordinary public key, host
certificate, unsupported algorithm, or malformed certificate is rejected.
3. An expired or not-yet-valid certificate is rejected deterministically under
a substituted clock.

**Implementation boundary.** Add the host package's direct declared
certificate-parsing dependency and a narrow parser/attribute value object.
Generate test certificates directly from that dependency or OpenSSH tools,
never through `ski`. Do not load a CA private key or independently reimplement
OpenSSH signature verification: `sshd`'s `TrustedUserCAKeys` remains the
cryptographic verification boundary.

**Done when.** Type-plus-base64 certificate input is parsed independently of
the issuer, and every unsupported or invalid credential fails closed.

## 2.3 Implement the pure offline authorization decision

**Stories.** US-4, US-5, and US-7.

**Outcome.** Given a validated local policy and a parsed offered certificate,
the host package makes one deterministic self-login/group decision without any
issuer or network dependency.

**Behavioural tests, in order:**

1. A current Ed25519 user certificate whose CA fingerprint equals policy,
   `key_id` equals the requested local account, identity principal equals that
   account, and signed group claims intersect `allowed_groups` returns the
   lexicographically first permitted group principal.
2. A CA-fingerprint mismatch, requested-account/key-ID mismatch, missing
   canonical identity principal, missing groups, duplicate principals,
   duplicate groups, malformed principals, or an unrecognised extra principal
   denies the request.
3. A certificate with no locally allowed group—or a valid policy with an empty
   allowed-group list—denies the request.
4. The decision path neither opens a database nor reads environment/dotenv,
   user directories, cache, CA private key, network resource, or mutable
   runtime state.

**Implementation boundary.** Create one deep, pure authorization service that
accepts the policy, parsed attributes, supplied `%F`, and target account, and
returns either one permitted principal or a denial value. Canonical identity
and `group:<name>` grammar must be defined in this host project rather than
borrowed from issuer implementation. Do not add account switching, user
provisioning, remote group lookup, KRL use, or certificate extensions.

**Done when.** Behavioural decision tests demonstrate strict certificate-bound
self-login, deterministic group selection, and complete fail-closed handling.

## 2.4 Wire the OpenSSH command interface to the decision

**Stories.** US-3, US-4, and US-5.

**Outcome.** The actual `AuthorizedPrincipalsCommand` invocation has the exact
OpenSSH stdout/exit contract: one allowed principal on success and no standard
output on every denial.

**Behavioural tests, in order:**

1. Invoking `ski-authorize --config PATH --ca-fingerprint %F TARGET %t %k`
   with the valid fixture exits zero and writes precisely one permitted group
   principal followed by one newline to stdout.
2. Every configuration, certificate, fingerprint, binding, principal, or group
   denial exits non-zero and writes no stdout; safe diagnostics, if any, are
   limited to stderr and never include raw certificate data, policy contents,
   private key material, agent data, passwords, TOTP material, issuer state,
   or complete environment values.
3. Argument omission, reordering, unexpected extra positional data, and
   `--check-config` mixed with sshd arguments fail closed.

**Implementation boundary.** Make the console entry point adapt the public
policy parser, certificate parser, and pure decision service. Preserve the
argument order used by the packaged fragment. Do not add logging transports,
debug mode, automatic configuration reload, issuer calls, or a daemon.

**Done when.** Subprocess tests prove an OpenSSH-compatible success/denial
interface and no accidental principal output.

## 2.5 Write target-host installation and OpenSSH configuration guidance

**Stories.** US-2 and US-3.

**Outcome.** An operator can deliberately transfer public CA material and
install/configure the local helper without treating the issuer as a host
deployment system.

**Behavioural tests, in order:**

1. The target-host guide directs the issuer operator to use `ski ca public-key`
   and compare its output with the public fingerprint shown by `ski ca show`;
   it never instructs copying a private CA key, SQLite database, dotenv file,
   user key, agent material, or KRL in this epic.
2. The guide gives exact root-owned, non-symlink layout and installation steps
   for `/opt/ski-authorize`, `/opt/ski-authorize/config/user-ca.pub`,
   `/opt/ski-authorize/config/authorization.toml`, and the sole external
   `/etc/ssh/sshd_config.d/60-ski-authorize.conf` fragment.
3. The documented fragment, sample asset, and command help agree exactly on
   the `%F %u %t %k` helper call, `ski-authz` command account,
   `TrustedUserCAKeys`, Ed25519 CA algorithm policy, disabled forwarding
   baseline, future-commented KRL, OpenSSH 9 requirement, `sshd -t`, and the
   RHEL-family vs Debian/Ubuntu reload command distinction.
4. The guide documents the 25-hour offline group-removal window, the office to
   production firewall boundary, and the fact that Debian/Ubuntu instructions
   are documented but not tested in this epic.

**Implementation boundary.** Add a concise target-host guide in `docs/` and
link it from the existing operational documentation as appropriate. Update
the packaged sample comments only where documentation reveals a contract drift.
The installation script explains manual issuer-side pickup and host-side
placement but performs no remote copy. Do not add an enrollment command,
configuration-management integration, CA distribution, or KRL deployment.

**Done when.** Documentation-contract tests keep instructions, package assets,
and the public CLI synchronized and explicitly bounded.

## 2.6 Add host-boundary regressions and manual Rocky UTM smoke instructions

**Stories.** US-6 and US-7.

**Outcome.** Automated tests provide deterministic evidence for the helper;
the guide provides a manual, repeatable Rocky Linux 9.x UTM verification that
proves a production-style host authorizes locally with no issuer reachability.

**Behavioural tests, in order:**

1. Automated host-package tests cover the complete permitted path and each
   denied category: other CA, wrong target account, identity/group grammar
   failure, disallowed group, empty policy groups, fingerprint mismatch,
   malformed policy, unavailable helper/configuration, ordinary key, and
   unsupported key/CA algorithm.
2. Package/source dependency and black-box command tests prove the host
   artifact contains no issuer endpoint, credential, dotenv lookup, SQLite
   path, remote policy client, telemetry exporter, listener, daemon, or
   configuration-management client.
3. A documentation test confirms a manual Rocky 9.x UTM procedure that
   installs only the host artifact, CA public key, policy, and sshd fragment;
   creates a pre-existing ordinary local account; validates/reloads sshd; and
   demonstrates the accepted and denied cases above.
4. The smoke procedure explicitly verifies the test host has no issuer process,
   issuer SQLite state, issuer credential, or route into the office network,
   and limits diagnostics to non-secret material.

**Implementation boundary.** Extend normal package/unit/command tests only.
Write the UTM procedure as manual operator instructions, including OpenSSH 9
version verification and SELinux-enforcing troubleshooting/validation for
Rocky. Do not build UTM provisioning, remote test execution, a pytest marker,
CI job, VM image builder, host mutator, another security review, or a future
KRL/CA-rotation feature.

**Done when.** The automated suite and manual Rocky smoke guide give bounded
evidence that production authorization is local, offline, least-privileged,
and fail-closed; the next security review remains scheduled after Epic 6.
