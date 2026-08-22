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

## Rocky Linux 9.x UTM smoke checklist (Epic 5, manual)

This is a repeatable operator check, not an automated test or a VM
provisioner. Take a disposable Rocky Linux 9.x UTM snapshot and verify the
guest's OpenSSH version is 9 or later. The guest receives only the
`ski-authorize` host artifact, `user-ca.pub`, the reviewed policy, and the
OpenSSH fragment. Do not copy the issuer SQLite file, dotenv file, CA private
key, or any issuer credential into the guest.

**Recorded result (2026-08-22): passed.** The manual successful-path test
accepted an Ed25519 user certificate signed by the configured user CA and
opened a session for the existing local account. The OpenSSH journal recorded
the certificate serial and trusted CA fingerprint.

1. Install the package with `sudo ./install.sh`, install the public key and
   policy under the exact `/opt/ski-authorize/config/` paths, install the
   fragment under `/etc/ssh/sshd_config.d/60-ski-authorize.conf`, and confirm
   with `namei -l` and `find -L /opt/ski-authorize -type l` that the tree is
   root-owned and contains no symlinks.
2. Create or select a pre-existing local account, for example
   `sudo useradd --create-home --shell /bin/bash test-user`. This account is
   created by the host operator, never by the helper. Set the policy to allow
   the signed `group:platform-ops` principal and verify the CA fingerprint
   against `ski ca show` before shipping the public key.
3. Run `sudo sshd -t`, check `getenforce` is `Enforcing`, and reload with
   `sudo systemctl reload sshd`. Record `ssh -V`, `sudo sshd -T`, and the
   ownership/mode checks as non-secret evidence.
4. From a client on the office side, obtain a current certificate for
   `test-user` from the issuer. Keep the private key and agent on that client;
   only the certificate's public material crosses the firewall as part of the
   SSH authentication. With the certificate loaded in the client agent, run
   `ssh -o IdentitiesOnly=no test-user@ROCKY_UTM_ADDRESS` and confirm that the
   login succeeds and the target account is `test-user`.
5. Confirm the helper's fail-closed cases. Each attempt must be rejected with
   no shell: use the same certificate as `test-other` (wrong target account),
   use a certificate carrying only a group not listed by the host policy,
   temporarily replace the policy fingerprint with another valid fingerprint,
   and try an ordinary un-certified Ed25519 key. After each policy edit run
   `sshd -t` and reload; restore the reviewed policy and reload it again.
6. Verify the offline boundary while testing: no `ski serve` process is
   running in the guest, no issuer SQLite or dotenv state exists below
   `/opt/ski-authorize`, and the guest routing/firewall policy has no route to
   the corporate office issuer network. The helper must still authorize or
   deny using only its local files and the certificate offered by OpenSSH.
7. If SELinux reports an AVC, capture the audit record with
   `sudo ausearch -m AVC -ts recent` and correct the labelled, root-owned
   installation or policy. Do not disable SELinux or broaden the helper's
   permissions as a workaround. Remove temporary accounts and credentials
   after the snapshot test.

This checklist intentionally does not test Debian or Ubuntu, distribute a
KRL, or rotate a CA. Do not automate UTM: those activities are outside Epic 5;
the next security review is scheduled after Epic 6.
