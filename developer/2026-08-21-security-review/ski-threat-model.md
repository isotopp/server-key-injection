# `ski` threat model

## Scope

`ski` is an SSH certificate issuer. A client on the corporate office network
connects to the issuer with agent forwarding, authenticates using a password
and TOTP, and receives a fresh SSH user key plus a 25-hour certificate in the
client's agent. The current SQLite identity store and virtual production hosts
are a demonstration. A later production deployment will use an external
identity provider and distribute trust material to production hosts which
cannot initiate connections into the office network.

## Assets and security objectives

- The user-CA private key must remain confidential and must sign only intended,
  canonical user and group principals.
- The issuer SSH host key, password verifiers, TOTP secrets, SQLite state, and
  CA event history must remain confidential and integrity-protected.
- A certificate must be issued only after both authentication factors succeed
  and the group snapshot is obtained for that same canonical identity.
- Agent injection must affect only the client agent explicitly forwarded to the
  trusted issuer; unrelated agent identities must remain untouched.
- The issuer must remain available to legitimate office users needing a daily
  credential renewal.
- Operational evidence must permit investigation without logging passwords,
  TOTP secrets, private keys, agent data, or complete environment contents.

## Components and trust boundaries

| Boundary                       | Trusted side                                                                 | Untrusted or constrained side                                                | Required behavior                                                                                             |
|--------------------------------|------------------------------------------------------------------------------|------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------|
| Client to issuer SSH transport | Issuer daemon and its pinned host identity                                   | Corporate-network client, VPN endpoint, and supplied SSH/TOTP/password input | Authenticate before issuance; do not trust a client claim of identity or group.                               |
| Forwarded agent channel        | The user's explicitly forwarded agent                                        | Remote client process and agent protocol messages                            | Create/inject only a fresh issuer credential; avoid deleting unrelated identities.                            |
| Identity adapter               | Canonical identity, password verification, TOTP verification, group snapshot | Demo SQLite now; LDAP, Active Directory, or Okta later                       | Bind factors and groups to the same canonical enabled identity; fail closed on unavailable or malformed data. |
| CA and state filesystem        | Dedicated service account and protected service home                         | Other local accounts, deployment tooling, backups, configuration management  | Preserve confidentiality and integrity; reject unsafe paths in a production mode.                             |
| Issuer to production hosts     | Public CA key, signed principals, host-local policy, optional KRL            | Production network separated by firewall from the office                     | Production makes offline authorization decisions and never needs an issuer connection during login.           |
| Operator CLI and systemd       | Approved OS-level operator and fixed `ski.service` unit                      | Arbitrary local callers without the service account's filesystem authority   | Mutations are controlled by OS account/file permissions; lifecycle is systemd-owned.                          |

## Attacker capabilities

- A compromised or malicious office endpoint can make SSH connections, choose a
  username, submit arbitrary keyboard-interactive responses, and forward an
  agent it controls.
- A network attacker outside the office has no direct route to the issuer, but
  may gain access through the corporate VPN or a compromised endpoint.
- A local account without access to the dedicated `ski` home may read or alter
  any accidentally exposed filesystem path; it cannot legitimately access a
  correctly installed service home.
- A user with access to the `ski` account or writable issuer state can already
  change state with SQLite tooling. This is an accepted OS authorization
  boundary, not an application-level administrator role.
- A production host is not assumed able to contact the issuer.

## Security invariants

1. No private CA key, generated user private key, password, TOTP secret, or
   agent payload is stored in logs or sent to production hosts.
2. The issuer requires both factors and a current group snapshot before it opens
   the forwarded agent for issuance.
3. Certificate identity, key ID, and first principal use the same canonical
   username; remaining principals are canonical `group:` values.
4. The private user key exists only in memory and the forwarded agent for its
   lifetime; it is never written under the user's home directory.
5. The service owns its sockets. systemd owns lifecycle, receives logs through
   journald, and runs under the dedicated service account.
6. All state, CA files, environment files, and parent directories are owned by
   the installation account, non-symlinked, and protected by the account's
   mode-0700 home.
7. Production authorization remains offline: a host uses its local CA public
   key, policy, and optional configuration-managed KRL; it does not call back
   into the office issuer.

## Primary abuse cases

- **Credential issuance with stolen factors:** limit online guessing and do not
  disclose whether an account exists; bind successful factors and current
  groups before signing.
- **Issuer or filesystem compromise:** protect the CA and SQLite secrets with a
  dedicated account, secure directories, protected backups, and startup checks.
- **Forwarded-agent misuse:** require explicit agent forwarding to the trusted
  issuer, issue one fresh credential, and prove ownership before removal.
- **Privilege escalation on a future production host:** make host policy accept
  only the signed user/group principal allowed for that host and default SSH
  forwarding capabilities to deny.
- **Revoked or removed access persisting:** keep the certificate lifetime at 25
  hours, make group changes affect new credentials, and later distribute a KRL
  through configuration management for earlier rejection where enabled.
- **Operational blind spots:** record safe request IDs, identities, decisions,
  and certificate serials without secret-bearing fields; verify state integrity
  and preserve append-only audit events.

## Assumptions and exclusions

- Correct NTP is an operational prerequisite.
- Corporate network controls reduce direct Internet exposure, but compromised
  office endpoints and VPN clients remain in scope.
- The current SQLite identity store, empty KRL, and no production-host trust
  are demo limitations. They must not be reused as the production identity or
  authorization design.
- Production host trust, revocation materialization, CA rotation, and an
  external identity adapter require a new review when implemented.

Repository: ski
Version: afdb488d207813e12b20d17d0865378b51a32212
