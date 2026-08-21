# Installing `ski` under systemd

The unit in [`ski.service`](ski.service) is a reviewed template. Adapt the
executable, account, and filesystem paths to the host before installing it. It
does not create a socket unit: `ski` owns its IPv4 and IPv6 listening sockets.
The application installation and all mutable files are confined to
`/home/ski`; only the systemd unit registration below is root-owned system
metadata.

## Provision the service account and state

Create a dedicated account whose home directory contains the mutable service
state. The example unit expects the account's uv tool executable at
`/home/ski/.local/bin/ski` and uses `/home/ski/var/lib/ski` for persistent
state. The service account's home is `/home/ski`; its application-local `etc`
and `var` trees live below that home.

```console
sudo useradd --system --home-dir /home/ski --create-home \
  --shell /usr/sbin/nologin ski
sudo install -d -o ski -g ski -m 0700 /home/ski/var/lib/ski
sudo install -d -o ski -g ski -m 0700 /home/ski/etc
sudo install -d -o ski -g ski -m 0700 /home/ski/etc/keys
```

Install the distro's systemd development/runtime package before installing the
Python journald binding. For example, Debian-family hosts normally need
`libsystemd-dev`; Fedora-family hosts normally use `systemd-devel`. Then,
while checked out at the project revision to deploy, install the pre-built uv
tool as the `ski` account:

```console
sudo -u ski -H sh -lc \
  'cd /home/ski/ski && uv tool install . --with systemd-python'
```

The `--with systemd-python` supplement supplies the native journald binding in
the deployment environment. Development on platforms without libsystemd uses
the console event sink; do not replace the Linux deployment binding with JSON
file logging.

## Configure the first run

Create `/home/ski/etc/env` with the mandatory local database path and any issuer
settings supported by the deployed revision. The application still applies its
normal search order (`./.env`, `$HOME/.ski.env`, `/home/ski/etc/env`); values exported
by systemd's `EnvironmentFile` take precedence.

```console
sudo install -o ski -g ski -m 0600 /dev/null /home/ski/etc/env
sudoedit /home/ski/etc/env
```

Set the database, persistent Ed25519 CA paths, and ordinary extension policy;
all parent directories must already exist:

```dotenv
SKI_CA_DATABASE=/home/ski/var/lib/ski/ca.sqlite3
SKI_CA_PRIVATE_KEY=/home/ski/etc/keys/user_ca
SKI_CA_PUBLIC_KEY=/home/ski/etc/keys/user_ca.pub
SKI_CA_KRL=/home/ski/var/lib/ski/revoked.krl
ORDINARY_CERT_EXTENSIONS=pty
```

Initialize the CA once, while the service is stopped, using the same
configuration file. The command refuses existing material and prints only the
public fingerprint:

```console
sudo -u ski -H /home/ski/.local/bin/ski ca init
sudo -u ski -H /home/ski/.local/bin/ski ca show
sudo -u ski -H /home/ski/.local/bin/ski ca public-key
```

The private CA file belongs in a separately protected, readable-by-`ski` path
under `/home/ski/etc/keys`; `ProtectSystem=strict` and `ReadOnlyPaths=/home/ski/etc`
keep it read-only to the daemon. Do not put private keys in the unit file or
commit `/home/ski/etc/env` to the repository.

## Install and operate the unit

Copy the reviewed template after adapting paths, then let systemd load and
supervise it:

```console
sudo install -o root -g root -m 0644 /home/ski/ski/docs/systemd/ski.service \
  /etc/systemd/system/ski.service
sudo systemctl daemon-reload
sudo systemctl enable --now ski.service
sudo systemctl status ski.service
sudo systemctl reload ski.service
sudo systemctl stop ski.service
```

`Type=simple` means systemd reports the process as started once it has been
executed. That `active` state is not proof that configuration, SQLite state, or
listeners are ready. Confirm application readiness through the native journal
event instead:

```console
sudo journalctl -u ski.service SKI_EVENT=service_ready
sudo journalctl -u ski.service -o verbose
```

The daemon handles `SIGHUP` as an atomic configuration reload and `SIGTERM` as
bounded graceful shutdown. There is intentionally no `ski stop`, `ski reload`,
or `ski status` command; systemd owns those lifecycle operations.
