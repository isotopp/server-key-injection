# R2 — Thin CLI adapters over command workflows

## 1. Characterize the CLI contract

**Outcome.** Parser forms, output, exit status, redaction, and notification
semantics are protected before workflow extraction.

**Behavioural tests, in order:**

1. Characterize one read-only identity and one mutation command via `main()`.
2. Characterize invalid input, redacted output, a stopped service, and failed
   post-commit notification.

**Implementation boundary.** Use real temporary boundaries; do not test parser
internals or dispatcher implementation details.

## 2. Extract a command resource boundary

**Outcome.** One read-only identity workflow owns its resource lifetime outside
the top-level CLI module.

**Behavioural tests, in order:**

1. Move `user list` or `user show` and preserve exact result/output.
2. Prove resources close on success and safe failure through public behaviour.
3. Migrate the paired read-only identity command.

**Implementation boundary.** Use simple explicit functions/context records;
no global registry or class per command.

## 3. Centralize post-commit notification

**Outcome.** Mutation commands share durable-success/notification-failure
handling without losing command-specific success text.

**Behavioural tests, in order:**

1. Move one user mutation to shared notification handling.
2. Move the counterpart user mutation.
3. Move group and membership mutations one command family at a time.

**Implementation boundary.** Notify only after durable work. Do not claim the
mutation failed because a service notification failed.

## 4. Extract CA read workflows

**Outcome.** CA show, public-key, and log retrieval/rendering leave the
top-level CLI adapter.

**Behavioural tests, in order:**

1. Move one CA read command preserving redacted output and exit status.
2. Move log filtering/rendering while retaining stable order and bounded
   results.
3. Move remaining CA read commands.

**Implementation boundary.** R1 adapters own query filtering; workflows invoke
them and CLI renders results.

## 5. Extract CA initialization workflow

**Outcome.** CA file/database/compensation ordering is application work, not
argparse-handler work.

**Behavioural tests, in order:**

1. Move successful `ca init` and preserve files, state, and output.
2. Move one injected compensation branch, proving no partial active CA state.
3. Migrate remaining initialization failure branches.

**Implementation boundary.** Do not change CA policy, file locations, command
syntax, or sensitive-material handling.

## 6. Bind parser-selected handlers

**Outcome.** Parser-bound handlers replace the long conditional dispatcher;
`main()` remains the console entry point.

**Behavioural tests, in order:**

1. Bind one existing handler and preserve `main()` behaviour.
2. Migrate command families one at a time.
3. Remove the dispatcher with help, version, and invalid-command behaviour
   unchanged.

**Implementation boundary.** Parser construction remains in CLI; handlers take
explicit parsed arguments and dependencies.
