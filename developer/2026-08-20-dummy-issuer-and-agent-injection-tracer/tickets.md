# Dummy issuer and agent-injection tracer — tickets

## Implementation rules

Implement these tickets in order. During the code-generation step, begin each
ticket with one public, behavioural test and take only the smallest
red-green-refactor slices needed to satisfy it. Commit a completed ticket with
the git-commit skill before beginning the next one.

This epic remains test-only: it creates no durable CA, certificate, database,
KRL, configuration, or production-host authorization state. The only generated
private key is the ephemeral test identity held in memory for the duration of
an injection attempt.

## 1. Test issuer command and listener lifecycle

**Outcome.** `uv run ski serve --port 2222` runs an AsyncSSH test issuer in the
foreground and can be stopped cleanly.

**Behavioural tests, in order:**

1. The public CLI parser accepts `serve`, `--bind`, and `--port`; the documented
   tracer invocation selects port `2222`.
2. Starting the service on a loopback test address and an available unprivileged
   port makes an SSH listener reachable and reports its bound address.
3. Interrupting or cancelling the foreground service closes its listener and
   lets an automated test complete without binding port 22.

**Implementation boundary.** Add only the command dispatch and a small,
explicit test-issuer runtime around AsyncSSH. The runtime may generate an
in-memory SSH host key for the process; it must not read or write CA state.
Keep the public `serve` options compatible with the documented command surface,
but all tracer examples and integration tests use the explicit unprivileged
port `2222` (or a test-selected free port).

**Done when.** The lifecycle tests exercise a real local SSH handshake, and no
long-running service, socket, key, or temporary file remains after the test.

## 2. Forwarded-agent gate and single tracer request

**Outcome.** A session to the test issuer becomes a single tracer request only
when the client has requested SSH agent forwarding.

**Behavioural tests, in order:**

1. A client which opens the minimal tracer session without agent forwarding is
   rejected with a clear user-facing error and no injection is attempted.
2. A client which requests agent forwarding can open that session and reaches
   the tracer request boundary.
3. Unsupported session, forwarding, and channel requests fail closed rather
   than enabling an additional server capability.

**Implementation boundary.** Keep the server's permitted SSH interaction to
the minimal session/channel shape needed to trigger one tracer run. Obtain the
forwarded-agent endpoint from the authenticated server connection/session and
use it only for the later injection ticket. Do not add user authentication,
shell access, command execution, port forwarding, files, or an API endpoint.
Errors and logs may identify a request outcome, but must not include agent
messages, paths, or key material.

**Done when.** The rejection case proves that a non-forwarding client cannot
cause an agent request, while the forwarding case proves that the server has a
usable forwarded-agent connection.

## 3. In-memory disposable certificate factory

**Outcome.** Each successful tracer request has a newly generated private key
and a matching dummy OpenSSH user certificate signed by an in-memory disposable
test CA.

**Behavioural tests, in order:**

1. The factory creates a usable keypair and matching OpenSSH user certificate
   for a tracer request.
2. Two factory calls produce distinct user identities; neither returns nor
   persists the disposable CA private key.
3. The certificate and identity use the `test-` key-ID/comment prefix and a
   fixed one-hour validity interval.

**Implementation boundary.** Use AsyncSSH's real key and certificate objects,
not a fake certificate representation. Keep the test CA and generated user
private key in memory. Define the one-hour duration once as tracer-only
behaviour; do not introduce `.env` configuration or the later ordinary
certificate-lifetime setting.

**Done when.** Tests validate the generated credential's observable OpenSSH
metadata and validity without writing any private key or certificate fixture to
the repository or runtime filesystem.

## 4. Inject the disposable identity through the forwarded agent

**Outcome.** A forwarding-enabled tracer session adds its new one-hour dummy
identity, with certificate, to the caller's actual `ssh-agent`.

**Behavioural tests, in order:**

1. With a fresh local test agent and forwarded-agent connection, the tracer
   adds the generated key and certificate with a 3,600-second agent lifetime.
2. Listing that local agent shows the new `test-` identity and associated
   certificate.
3. An agent refusal or transport failure reports a non-sensitive error and does
   not report tracer success.

**Implementation boundary.** Connect to the agent only through the SSH
forwarding channel, then use AsyncSSH's agent client to add the in-memory
keypair and certificate with the one-hour lifetime constraint. Never use the
issuer's `SSH_AUTH_SOCK`, and never log, persist, or return private-key bytes
or agent protocol payloads.

**Done when.** An integration test starts an isolated local `ssh-agent`,
connects to the test issuer with agent forwarding, and verifies with
`ssh-add -l` (or its equivalent agent listing) that precisely the tracer
identity was added.

## 5. End-to-end tracer safety contract

**Outcome.** The documented tracer flow is repeatable, short-lived, and
demonstrably separate from persistent or production functionality.

**Behavioural tests, in order:**

1. A complete forwarding-enabled SSH session causes exactly one fresh
   `test-` identity to appear in an isolated test agent.
2. Repeating the session produces a distinct second tracer identity rather
   than reusing a key or certificate.
3. The test fixture's temporary agent, listener, and process resources are
   removed on both success and failure paths.

**Implementation boundary.** Assemble the preceding tickets only; do not add
SQLite, environment-driven configuration, passwords/TOTP, group claims,
production trust configuration, KRLs, systemd integration, or a production
authorization helper. Keep test diagnostics redacted and use non-sensitive
request correlation only.

**Done when.** A developer can follow a README-quality test command using port
`2222`, connect with agent forwarding, run `ssh-add -l`, and observe a
short-lived `test-` dummy certificate identity which no production host trusts.
