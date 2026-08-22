# Installing `ski-authorize` on a production SSH host

This guide describes the deliberate, offline trust hand-off from an issuer to
an OpenSSH target host. The host runs only the independently installable
`ski-authorize` helper. It does not contact `ssh.example.com`, read the
issuer's SQLite store, or perform a group lookup during login.

OpenSSH 9 or later is required. The complete procedure is manually verified
on a current Rocky Linux 9.x guest in UTM. Debian and Ubuntu instructions are
provided for operators, but are not tested by this epic. Keep NTP working on
both sides; the host evaluates certificate validity locally.

## Pick up public trust material from the issuer

Run these commands on the issuer as the installation user. `ca public-key`
prints only the public user-CA key. Compare its fingerprint with the
fingerprint printed by `ca show` through an independent channel before
shipping either value to a target host:

```console
uv run ski ca show
uv run ski ca public-key > user-ca.pub
```

Record the exact `SHA256:...` fingerprint from `ca show` for
`trusted_ca_fingerprint` and for the helper's `--ca-fingerprint` argument.
Transfer only the public key, the reviewed `ski-authorize` package, and the
site-specific policy to the target host using the site's configuration
management process. This project supplies no remote-copy or enrollment
command.

Never transfer the issuer's CA private key, SQLite database, identity data,
`.env` file, user private key, agent contents, or a KRL for this epic. KRL
generation and distribution are deferred to Epic 6.

## Install the protected host tree

On the target host, run the packaged installer as root from the checked-out
`packages/ski-authorize` directory (or from the reviewed package source):

```console
sudo ./install.sh
```

The installer creates the root-owned, non-symlink tree below and installs the
unprivileged `ski-authz` command account:

```text
/opt/ski-authorize/
├── bin/ski-authorize
├── cache/
├── config/
│   └── authorization.toml
├── python/
└── tools/
```

Every directory, interpreter, tool, executable, and configuration file below
`/opt/ski-authorize` must be owned by root and not writable by group or other
users. The helper account may read only the public policy it needs; it has no
issuer database, CA private key, login shell, or issuer network route.

Install the public CA key and the site policy as regular files, never as
symlinks:

```console
sudo install -o root -g root -m 0644 user-ca.pub \
  /opt/ski-authorize/config/user-ca.pub
sudo install -o root -g ski-authz -m 0640 authorization.toml \
  /opt/ski-authorize/config/authorization.toml
```

Start from the package samples, then replace the fingerprint and deliberately
review the allowed groups. An empty group list denies all certificate logins:

```toml
[ssh]
trusted_ca_fingerprint = "SHA256:..."
allowed_groups = ["group:platform-ops", "group:database-oncall"]
allow_self_login_only = true
```

The only ski-related file outside `/opt/ski-authorize` is the root-owned
OpenSSH fragment below. Do not create alternate paths or symlinks to these
files:

```console
sudo install -o root -g root -m 0644 \
  src/ski_authorize/examples/60-ski-authorize.conf \
  /etc/ssh/sshd_config.d/60-ski-authorize.conf
```

Review the installed fragment before enabling it. Its important contract is:

```text
TrustedUserCAKeys /opt/ski-authorize/config/user-ca.pub
CASignatureAlgorithms ssh-ed25519
AuthorizedPrincipalsCommand /opt/ski-authorize/bin/ski-authorize --config /opt/ski-authorize/config/authorization.toml --ca-fingerprint %F %u %t %k
AuthorizedPrincipalsCommandUser ski-authz
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
```

The `%F %u %t %k` values are supplied by OpenSSH in exactly that order: CA
fingerprint, local target account, certificate type, and certificate body.
`ski-authorize` returns one permitted `group:...` principal or no principal;
OpenSSH remains the cryptographic signature-verification boundary. The sample
leaves a future `RevokedKeys`/KRL line commented out and does not enable it.

## Validate and reload OpenSSH

Check the version and validate the complete configuration before any reload:

```console
ssh -V
sudo sshd -t
```

On Rocky/RHEL/Alma, reload the `sshd` service:

```console
sudo systemctl reload sshd
```

On Debian or Ubuntu, use the distro service name:

```console
sudo systemctl reload ssh
```

Do not enable the fragment until the CA fingerprint, policy groups, file
ownership, and existing local Unix accounts have been reviewed. The helper
does not create accounts or map one Unix account to another. A certificate's
`key_id` and identity principal must equal the existing target account.

## Offline security boundary

Clients authenticate to the issuer on the corporate office network and carry
their short-lived certificate through the firewall into production. Production
hosts have no route back to the office issuer. With the default 25-hour
certificate lifetime, removing a user from an issuer group prevents newly
issued certificates but an already issued certificate can continue to start
new sessions locally until it expires. This is the intentional offline gap;
future KRL distribution can shorten it.

For Rocky UTM verification, also confirm SELinux is enforcing and investigate
denials using the host's normal audit tooling rather than weakening the policy:

```console
getenforce
sudo ausearch -m AVC -ts recent
```

The manual acceptance procedure, including accepted and denied login cases,
is in the final section of this guide's Epic 5 smoke checklist and must be
performed without starting an issuer process or adding an office-network
route.
