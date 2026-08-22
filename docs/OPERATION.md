# Operating `ski`

This guide is for issuer operators and end users. Start with
[`README.md`](README.md) for the documentation map; use
[`TARGET-HOST.md`](TARGET-HOST.md) for the separately installed production
host.

The current implementation is a demo issuer. It runs as one foreground
`ski serve` process under systemd, stores its state in SQLite, and creates
short-lived ordinary certificates with the persistent Ed25519 CA configured in
`/home/ski/etc/env`. The independently installed production-host helper and
its offline OpenSSH configuration are documented in
[`TARGET-HOST.md`](TARGET-HOST.md); revocation and CA rotation remain later
work.

For target-host installation, CA public-key hand-off, policy review, and the
OpenSSH reload procedure, use [`TARGET-HOST.md`](TARGET-HOST.md). The issuer
does not install or remotely configure production hosts.

## Daily operator checks

Check the service and its readiness event:

```console
sudo systemctl is-active ski.service
sudo journalctl -u ski.service -S today
sudo journalctl -u ski.service SKI_EVENT=service_ready -n 1
```

Use the structured fields when investigating an issuance request. The journal
may contain request IDs, certificate serials, canonical users, and decisions;
it must never contain passwords, TOTP secrets, private keys, agent payloads, or
the complete environment.

Verify SQLite and CA-log consistency at least daily and after restoring state
or changing deployment files:

```console
sudo -u ski -H /home/ski/.local/bin/ski ca log verify
sudo -u ski -H /home/ski/.local/bin/ski ca log list --event certificate_issued
```

The log view is bounded and redacted. Use filters such as `--user`, `--serial`,
`--from`, and `--to` to investigate a specific request without dumping secret
or credential material.

## Regular maintenance

- Keep NTP synchronized. Certificate validity, the 25-hour renewal window, and
  future KRL expiry cleanup all depend on a correct clock.
- Back up `/home/ski/var/lib/ski/ca.sqlite3`, `/home/ski/etc/keys/user_ca`, its
  public key, and `/home/ski/var/lib/ski/revoked.krl` as one protected recovery
  set. The database
  contains demo password verifiers and TOTP secrets; encrypt backups and limit
  access. Test restoration without replacing the live CA.
- Check free space and ownership on `/home/ski/var/lib/ski`, `/home/ski/etc`,
  and `/home/ski/etc/keys`. The service account needs only the access granted by the
  reviewed unit.
- State and CA files must remain regular, non-symlink files owned by `ski:ski`
  without group or other write permission. An unsafe database, lock, or CA
  file causes a fail-closed startup or administrative command; stop the service
  before correcting ownership or mode and then verify a fresh readiness event.
- Review user and group membership changes:

  ```console
  sudo -u ski -H /home/ski/.local/bin/ski user list
  sudo -u ski -H /home/ski/.local/bin/ski group list
  sudo -u ski -H /home/ski/.local/bin/ski user show alice
  ```

- Disable an account promptly when it must no longer obtain credentials:

  ```console
  sudo -u ski -H /home/ski/.local/bin/ski user disable alice
  ```

  Remove or add a membership with `ski group member remove` or `ski group
  member add`. Mutating commands commit SQLite first and request a systemd
  reload when the service is active; if it is stopped, the next start reads the
  committed state.
- Treat changes to `/home/ski/etc/env`, CA files, and the unit as deployment events:
  validate them, run `systemctl reload ski.service`, and confirm a new
  `service_ready` event. A failed reload retains the previous working runtime
  configuration.

## Backup and recovery boundary

The protected recovery set is the SQLite database, its lock and journal files
when present, the CA private and public key files, and the materialized KRL
file. Treat the database as sensitive demo identity data: it contains password
verifiers, TOTP secrets, group membership, and issuance history. Use the
installing organization's encrypted backup system; `ski` does not upload,
rotate, retain, or restore backups for you.

For a planned recovery, stop the service before taking or restoring a backup:

1. Stop `ski.service` and confirm it is inactive.
2. Snapshot or restore the complete protected recovery set as one unit,
   preserving the `ski` owner, restrictive modes, and non-symlink file
   contract. Do not restore a database with a different CA key set.
3. Run `ski ca show`, `ski ca public-key`, and `ski ca log verify` as the
   service account before starting the service. Do not edit SQLite to simulate
   revocation or repair a failed integrity check.
4. Start the service, confirm `SKI_EVENT=service_ready` in journald, and
   perform one non-secret operational check before returning it to use.

The current demo has no implemented `ski ca revoke`, `ski ca reconcile`, or CA
rotation command. Do not present those as runnable recovery steps until Epic 6
delivers them. Preserve the database and CA files together until the later
revocation and rotation work is deployed.

Monitoring, alerting, journal retention, incident response, break-glass
access, backup scheduling, restore testing, and SELinux policy are deployment
responsibilities of the installing organization. They are not hidden features
of the issuer or host helper.

## End-user experience

Users need an existing `ssh-agent` and must explicitly forward it only to the
trusted issuer. Start a dedicated agent for a first test or a recovery drill:

```console
eval "$(ssh-agent -s)"
ssh-add -l || true
```

Request a certificate from the issuer:

```console
ssh -A -tt -p 2222 \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  alice@127.0.0.1
```

The issuer prompts for the user's password and current six-digit TOTP. On
success it prints a line like:

```text
Key loaded: alice serial=123456789 valid-until=2026-08-22T09:00:00+00:00
Groups: platform-ops
```

It then closes the session. The generated private key and matching signed
certificate are held in the forwarded agent, not written to the user's home
directory. `ssh-add -l` displays the corresponding `ED25519` and
`ED25519-CERT` entries; together they form one usable certificate credential.
The certificate expires exactly 25 hours after issuance, so users normally
repeat the issuer login once per day. A group membership change affects newly
issued certificates; it does not rewrite a credential already held by an
agent.

Forwarding the agent to an untrusted host is unsafe. Without `-A`, the issuer
must reject the request with `Agent forwarding is required.` If authentication
fails, no new credential should appear in the agent. Production hosts accept
these certificates only when separately configured with the trusted CA public
key, local policy, and `ski-authorize`; see [`TARGET-HOST.md`](TARGET-HOST.md).

## Lifecycle controls

systemd owns process lifecycle and the application owns its sockets:

```console
sudo systemctl reload ski.service   # SIGHUP: validate and reload
sudo systemctl stop ski.service     # SIGTERM: bounded graceful shutdown
sudo systemctl restart ski.service
```

The daemon listens on `--bind *` (both `0.0.0.0` and `::`) and port 22 by
default. For a local test, override them in the unit or run
`uv run ski serve --bind 127.0.0.1 --port 2222` in the foreground. There is no
application-level `ski stop` or `ski reload` command.
