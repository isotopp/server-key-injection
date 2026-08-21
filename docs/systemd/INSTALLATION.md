# Installing `ski` under systemd

The unit in [`ski.service`](ski.service) is a reviewed template. Adapt the
executable, account, and filesystem paths to the host before installing it. It
does not create a socket unit: `ski` owns its IPv4 and IPv6 listening sockets.

## Provision the service account and state

Create a dedicated account whose home directory is separate from the mutable
service state. The example unit expects the account's uv tool executable at
`/home/ski/.local/bin/ski` and uses `/var/lib/ski` for `HOME` and persistent
state.

```console
sudo useradd --system --home-dir /home/ski --create-home \
  --shell /usr/sbin/nologin ski
sudo install -d -o ski -g ski -m 0700 /var/lib/ski
sudo install -d -o root -g ski -m 0750 /etc/ski /etc/ski/keys
```

Install the distro's systemd development/runtime package before installing the
Python journald binding. For example, Debian-family hosts normally need
`libsystemd-dev`; Fedora-family hosts normally use `systemd-devel`. Then,
while checked out at the project revision to deploy, install the pre-built uv
tool as the `ski` account:

```console
sudo -u ski -H sh -lc \
  'cd /path/to/ski && uv tool install . --with systemd-python'
```

The `--with systemd-python` supplement supplies the native journald binding in
the deployment environment. Development on platforms without libsystemd uses
the console event sink; do not replace the Linux deployment binding with JSON
file logging.

## Configure the first run

Create `/etc/ski/env` with the mandatory local database path and any issuer
settings supported by the deployed revision. The application still applies its
normal search order (`./.env`, `$HOME/.ski.env`, `/etc/ski/env`); values exported
by systemd's `EnvironmentFile` take precedence.

```console
sudo install -o root -g ski -m 0640 /dev/null /etc/ski/env
sudoedit /etc/ski/env
```

At minimum, set a database whose parent already exists:

```dotenv
SKI_CA_DATABASE=/var/lib/ski/ca.sqlite3
```

Future CA key material belongs in a separately provisioned, readable-by-`ski`
path under `/etc/ski/keys`; `ProtectSystem=strict` and `ReadOnlyPaths=/etc/ski`
keep it read-only to the service. Do not put private keys in the unit file or
commit `/etc/ski/env` to the repository.

## Install and operate the unit

Copy the reviewed template after adapting paths, then let systemd load and
supervise it:

```console
sudo install -o root -g root -m 0644 docs/systemd/ski.service \
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
