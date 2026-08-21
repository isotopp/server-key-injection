# Security review implementation tickets

## Scope and processing rules

This ticket set implements only the bounded mitigations accepted in
[`security-review.md`](security-review.md): SR-2 secure issuer-file handling and
SR-3 dummy Argon2 verification. SR-1 is an explicitly accepted risk and creates
no implementation work.

Process tickets in order. For every ticket, use one red-green-refactor cycle at
a time: add one behavioural test, run it and observe RED, make the smallest
public implementation change, run the focused test to GREEN, then continue.
Commit each completed ticket separately. Do not start the next ticket until its
predecessor is committed.

The existing public entry points remain the interfaces under test:
`StateDatabase.open()`, `load_validated_active_ca()`, `CAFileWriter.install()`,
and `SqliteIdentityStore.verify_password()`. Do not add a configuration flag,
network control, timing benchmark, or issuer-side rate limiting.

## Ticket 1 — Define the bounded secure-file policy

**Source:** SR-2

Create one small, focused filesystem-policy module which validates an existing
issuer-managed file before it is opened or trusted. Its interface must take a
path plus the expected effective owner and group, and raise a typed,
safe-to-display application error without leaking path contents.

Implement the following observable policy:

- A candidate must be a regular file, not a directory, device, FIFO, socket, or
  symlink.
- Its owner UID and group GID must equal the expected values.
- Its mode must not grant write permission to the group or to others.
- Validation must use metadata which does not follow a final-component symlink.

RED/GREEN slices, in this order:

1. A correctly owned regular file without group/other write permission is
   accepted.
2. A symlink is rejected, including one whose target is otherwise acceptable.
3. A non-regular file is rejected.
4. A file with a wrong owner/group is rejected.
5. A group- or world-writable file is rejected.

Use test-owned temporary files and, for owner/group mismatch coverage, pass a
deliberately different expected UID/GID rather than attempting privileged
`chown`. Skip only platform-specific file-type cases which cannot be created
safely. Do not use wall-clock assertions or test private helper names. Keep the
validator reusable by the state and CA modules, but do not broaden it into
recursive ancestor-path validation.

**Done when:** focused policy tests pass and the public error contains no secret
material or full file contents.

## Ticket 2 — Protect SQLite state and its ownership lock

**Source:** SR-2

Apply Ticket 1's policy to the issuer SQLite database and its `.lock` file.
Existing safe state must be validated before SQLite opens it. New database and
lock files created by `StateDatabase.open()` must be created with the existing
restricted permissions and validated before use. Use the effective UID and GID
of the running service process as the expected ownership; this matches the
dedicated systemd service account contract without a new configuration setting.

RED/GREEN slices, in this order:

1. `StateDatabase.open()` continues to create and reopen a safe database and,
   when `owner=True`, a safe lock file.
2. Opening a database path which is a symlink fails before SQLite connects.
3. Opening an existing group- or world-writable database fails.
4. Acquiring daemon ownership fails when the existing lock file is a symlink,
   non-regular file, wrongly owned/grouped, or group/world writable.
5. A policy failure releases any partial lock or connection state and preserves
   the existing safe error boundary (`StateError`).

Exercise the public `StateDatabase.open()` interface rather than the new
validator directly for integration coverage. Keep the current single-instance
locking semantics and do not inspect parent directories beyond the documented
scope.

**Done when:** state/lock failures fail closed before state is used, ordinary
state tests still pass, and no sensitive path data is added to errors or logs.

## Ticket 3 — Protect CA material during initialization and loading

**Source:** SR-2

Apply the same policy to every CA file: private key, public key, and KRL.
`load_validated_active_ca()` must validate the private and public key files
before reading bytes. `CAFileWriter.install()` must refuse unsafe existing
targets and validate each atomically installed file before declaring success.
The KRL generated during initialization is also subject to the policy.

RED/GREEN slices, in this order:

1. `ski ca init`-level CA setup still produces files which the loader accepts.
2. Loading rejects a symlinked private key or public key before import.
3. Loading rejects a wrong-owner/group or group/world-writable private/public
   key without exposing key material.
4. CA initialization rejects unsafe pre-existing target files, including a
   symlink, rather than replacing or trusting them.
5. The successfully installed private key, public key, and KRL all satisfy the
   policy; an unsafe result triggers existing compensating cleanup and a
   `CAFileError`.

Use public CA command/workflow interfaces in at least one end-to-end test; use
the file writer only for focused atomic-installation edge cases. Do not change
CA algorithms, certificate policy, key persistence design, or KRL semantics.

**Done when:** all CA material is checked at each open/create boundary, failed
initialization leaves no newly created unsafe CA material, and existing CA and
runtime tests pass.

## Ticket 4 — Equalize unknown and disabled password verification work

**Source:** SR-3

Make `SqliteIdentityStore.verify_password()` perform one Argon2 verification
against a non-secret dummy verifier when the username does not resolve or the
user is disabled, before returning `False`. The dummy verifier must be valid for
the configured `PasswordHasher` and must not contain any real user password.
Known enabled-user authentication and opportunistic password rehashing must
retain their current behaviour.

RED/GREEN slices, in this order:

1. Unknown usernames still return `False`, but exercise the configured hasher's
   verification path with the dummy verifier.
2. Disabled users still return `False`, and exercise the same dummy-verifier
   path without verifying their stored password verifier.
3. A known enabled user accepts the right password and rejects the wrong one as
   before.
4. A known enabled user which needs rehashing is rehashed only after a valid
   password, never for the dummy path.

Use the existing injectable password-hasher boundary to assert the observable
verification contract; do not add a wall-clock timing test, sleeps, or rate
limiting. Keep all exception handling fail-closed and do not log credentials or
verifier values.

**Done when:** unknown and disabled paths consume a valid dummy Argon2
verification, enabled-user behaviour remains unchanged, and the focused
identity/authentication tests pass.

## Ticket 5 — Full regression and operational contract check

**Source:** SR-2 and SR-3

After Tickets 1–4 are green, run the required full verification sequence:

```console
uv run ruff format
uv run ruff check --fix
uv run ty check
uv run pytest
```

Review the installation and operation documentation against the implemented
behaviour. Update only statements made inaccurate by the accepted bounded
mitigations—for example, if startup now rejects unsafe state or CA files. Do
not add documentation for rejected SR-1 rate limiting or for unimplemented
production identity/KRL work.

**Done when:** all required checks pass, the docs accurately describe the
bounded file contract, and the final ticket commit contains only the necessary
code, tests, and documentation changes.
