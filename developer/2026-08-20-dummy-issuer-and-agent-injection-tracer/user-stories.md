# Dummy issuer and agent-injection tracer

## Epic outcome

Prove the complete, harmless path from a user's forwarded `ssh-agent` through
the issuer and back to that agent. A test user connects to the test issuer,
receives an ephemeral keypair and a short-lived dummy OpenSSH user certificate,
and can see the resulting identity with `ssh-add -l`.

The dummy certificate grants no production access: no production host trusts
its disposable CA.

## Scope and boundaries

This epic implements only the tracer described in
[Epic 1 — Dummy issuer and agent-injection tracer](../architecture.md#epic-1--dummy-issuer-and-agent-injection-tracer).

It does not add persistent CA state, SQLite state, `.env` configuration,
password/TOTP authentication, user/group claims, production-host authorization,
KRLs, or systemd deployment. Those belong to later epics.

## User stories

### US-1: Start a test issuer

As a developer, I can start a foreground test issuer with `uv run ski serve`
on port `2222`, so that I can exercise the
SSH transport without a production deployment.

**Acceptance criteria:**

- The command starts an AsyncSSH server and reports the address on which it is
  listening.
- The tracer's documented invocation is `uv run ski serve --port 2222`.
- The server remains in the foreground and stops cleanly when interrupted.
- The server accepts only the minimal SSH session/channel shape required for
  this tracer.
- Automated tests can start and stop the server without binding the production
  default port.

### US-2: Request agent forwarding from the test client

As a developer using a local `ssh-agent`, I can connect to the test issuer with
agent forwarding enabled, so that the issuer can use the forwarding channel
for this tracer.

**Acceptance criteria:**

- A connection which does not request agent forwarding is rejected with a clear
  error and does not inject an identity.
- A connection which requests forwarding exposes only the agent channel needed
  by the tracer.
- Connection, channel, and forwarding failures are surfaced without logging
  agent payloads or private-key material.

### US-3: Create a disposable dummy certificate identity

As the test issuer, I generate a fresh ephemeral keypair and dummy user
certificate for each successful tracer request, so that the agent-injection
path uses real OpenSSH credential objects without creating durable access.

**Acceptance criteria:**

- Every successful request receives a newly generated keypair and certificate.
- The certificate is signed by a disposable test CA which is not configured on
  any production host.
- The certificate has a fixed one-hour test-only validity and the key ID and
  comment begin with `test-`.
- Private keys exist only in process memory while they are being added to the
  forwarded agent; they are never written to a file, log, response, or test
  fixture.

### US-4: Inject and inspect the dummy identity

As a developer, after a successful tracer request I can use `ssh-add -l` to
see the newly added dummy identity, so that I have end-to-end evidence that
the issuer reached my local agent.

**Acceptance criteria:**

- The issuer adds the private key and associated certificate through the
  forwarded agent protocol.
- The agent identity has a one-hour lifetime, no longer than the dummy
  certificate's validity.
- The issuer reports successful injection without disclosing private material.
- Automated integration tests use a real local test agent to verify that the
  resulting identity is present.

### US-5: Keep the tracer harmless and observable

As a security reviewer, I can verify that the tracer cannot accidentally grant
production access and that failures leave no durable credential material.

**Acceptance criteria:**

- No persistent database, CA file, KRL, `.env` configuration, or production
  authorization helper is introduced by this epic.
- Logs identify the request outcome with non-sensitive correlation data only.

## Decisions made during story refinement

- The developer-facing tracer uses port `2222`; the architectural production
  default of port 22 is not part of this epic.
- Dummy certificates and their injected agent identities have a fixed one-hour
  lifetime; this epic has no lifetime option.
- The `test-` prefix identifies tracer-owned key IDs and comments, allowing
  future tracer cleanup to distinguish them from unrelated agent identities.
