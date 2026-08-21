# Operating `ski`

The current implementation is a demo issuer. It runs as one foreground
`ski serve` process under systemd, stores its state in SQLite, and creates
short-lived ordinary certificates with the persistent Ed25519 CA configured in
`/home/ski/etc/env`. Production-host trust, offline authorization, revocation, and
CA rotation are documented architecture targets but are not complete in this
demo.

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

The current demo has no implemented `ski ca revoke`, `ski ca reconcile`, or CA
rotation command. Do not simulate revocation by editing SQLite or deleting CA
files. Preserve the database and CA files together until the later revocation
and rotation work is deployed.

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
fails, no new credential should appear in the agent. The current demo's
certificates are not accepted by production hosts until the later host-trust
and authorization epics are implemented.

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
