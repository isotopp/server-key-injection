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

## Clone and install

Clone the repository from its `origin` GitHub repository and install the
development environment:

```console
git clone git@github.com:isotopp/server-key-injection.git ski
cd ski
uv sync
```

Create the service account and its state directories. Keep the CA private key
under a dedicated directory that is readable only by the service account:

```console
sudo useradd --system --home-dir /home/ski --create-home \
  --shell /usr/sbin/nologin ski
sudo install -d -o ski -g ski -m 0700 /var/lib/ski
sudo install -d -o root -g ski -m 0750 /etc/ski
sudo install -d -o ski -g ski -m 0700 /etc/ski/keys
```

Install the checked-out revision as the service account. This keeps the
runtime executable and its dependencies outside the source checkout:

```console
sudo -u ski -H sh -lc \
  'cd /path/to/ski && uv tool install . --with systemd-python'
```

Replace `/path/to/ski` with the absolute clone path.

## Configure and initialize the CA

Create `/etc/ski/env` and set the paths below. Parent directories must exist;
`ski ca init` refuses to replace existing CA material.

```console
sudo install -o root -g ski -m 0640 /dev/null /etc/ski/env
sudoedit /etc/ski/env
```

```dotenv
SKI_CA_DATABASE=/var/lib/ski/ca.sqlite3
SKI_CA_PRIVATE_KEY=/etc/ski/keys/user_ca
SKI_CA_PUBLIC_KEY=/etc/ski/keys/user_ca.pub
SKI_CA_KRL=/var/lib/ski/revoked.krl
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
sudo install -o root -g root -m 0644 docs/systemd/ski.service \
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
