# Installing and initializing `ski`

This is the installation guide for the current demo issuer. It creates a
single systemd-managed service, a persistent Ed25519 user CA, one demo user,
and one group membership. The demo stores password verifiers, TOTP secrets,
and group membership in SQLite; do not use it as a production identity
backend.

## Prerequisites

Install Python 3.12 or later, `git`, `uv`, and the system package required by
the native journald binding. Debian-family systems normally call that package
`libsystemd-dev`; Fedora-family systems normally call it `systemd-devel`.

The service account must be able to bind the configured port. The example unit
uses `CAP_NET_BIND_SERVICE` for port 22. Adapt the unit and firewall rules to
the host's policy before exposing it.

Create the service account and its state directories. Keep the CA private key
under a dedicated directory that is readable only by the service account:

```console
sudo useradd --system --home-dir /home/ski --create-home \
  --shell /usr/sbin/nologin ski
sudo install -d -o ski -g ski -m 0700 /home/ski/var/lib/ski
sudo install -d -o ski -g ski -m 0700 /home/ski/etc
sudo install -d -o ski -g ski -m 0700 /home/ski/etc/keys
```

## Clone and install

Clone the repository from its `origin` GitHub repository into the installation
user's home and install the development environment there:

```console
sudo -u ski -H git clone git@github.com:isotopp/server-key-injection.git \
  /home/ski/ski
sudo -u ski -H sh -lc 'cd /home/ski/ski && uv sync'
```

Install the checked-out revision as the service account. This keeps the
runtime executable and its dependencies outside the source checkout:

```console
sudo -u ski -H sh -lc \
  'cd /home/ski/ski && uv tool install . --with systemd-python'
```

All application code, the uv tool, configuration, CA files, and SQLite state
now live below `/home/ski` and are owned by `ski`. The systemd unit installed
below is the sole root-owned deployment metadata required by a system service.

## Configure and initialize the CA

Create `/home/ski/etc/env` and set the paths below. Parent directories must exist;
`ski ca init` refuses to replace existing CA material.

```console
sudo install -o ski -g ski -m 0600 /dev/null /home/ski/etc/env
sudoedit /home/ski/etc/env
```

```dotenv
SKI_CA_DATABASE=/home/ski/var/lib/ski/ca.sqlite3
SKI_CA_PRIVATE_KEY=/home/ski/etc/keys/user_ca
SKI_CA_PUBLIC_KEY=/home/ski/etc/keys/user_ca.pub
SKI_CA_KRL=/home/ski/var/lib/ski/revoked.krl
ORDINARY_CERT_EXTENSIONS=pty
```

Initialize and inspect the public CA state while the service is stopped:

```console
sudo -u ski -H /home/ski/.local/bin/ski ca init
sudo -u ski -H /home/ski/.local/bin/ski ca show
sudo -u ski -H /home/ski/.local/bin/ski ca public-key
```

Distribute only the output of `ca public-key` to systems that will eventually
trust this CA. Never copy the private CA key to a production host, commit it,
or place it in a unit file. The current demo creates an empty KRL file; KRL
revocation workflows are part of a later epic.

### File safety contract

At every state or CA file boundary, `ski` accepts only regular files that are
not symlinks, are owned by the service account and group, and do not grant
write permission to the group or to other users. This applies to the SQLite
database and its ownership lock, and to the CA private key, public key, and
KRL created by `ski ca init`. The service and administrative commands fail
closed with a generic error when an existing file violates this contract;
`ca init` also removes newly installed material if post-install validation
fails. Keep the configured paths as direct files below the service account's
0700 home rather than replacing them with symlinks.

## Create the first user and group

Create a user. The command prompts for a password and prints the TOTP secret
and provisioning URI once; deliver that enrollment material to the user over a
trusted channel.

```console
sudo -u ski -H /home/ski/.local/bin/ski user add alice
```

Create a group and add the user to it:

```console
sudo -u ski -H /home/ski/.local/bin/ski group add platform-ops
sudo -u ski -H /home/ski/.local/bin/ski group member add platform-ops alice
sudo -u ski -H /home/ski/.local/bin/ski user show alice
sudo -u ski -H /home/ski/.local/bin/ski group show platform-ops
```

The group is represented in an issued certificate as the signed principal
`group:platform-ops`. A later production-host authorization helper will decide
whether that principal is allowed on a particular host; the current demo does
not yet make production hosts trust the CA.

## Install and start systemd

Install the reviewed unit, then start the daemon:

```console
sudo install -o root -g root -m 0644 /home/ski/ski/docs/systemd/ski.service \
  /etc/systemd/system/ski.service
sudo systemctl daemon-reload
sudo systemctl enable --now ski.service
sudo systemctl status ski.service
```

Confirm application readiness in journald:

```console
sudo journalctl -u ski.service SKI_EVENT=service_ready
```

For the complete hardening assumptions, path ownership, reload behavior, and
systemd troubleshooting notes, see
[`docs/systemd/INSTALLATION.md`](systemd/INSTALLATION.md).
