# R4 — Single issuance and agent-compensation workflow

## 1. Characterize issuance ordering

**Outcome.** Public forwarded-agent tests protect existing success and failure
outcomes before orchestration moves.

**Behavioural tests, in order:**

1. Successful issuance prepares a credential, adds it to the forwarded agent,
   then durably records it.
2. Persistence failure after add removes only the issuer-owned new credential
   and retains unrelated agent identities.
3. Prepare, agent, duplicate-serial, and failure-event branches retain current
   session results and durable-event outcomes.

**Implementation boundary.** Test SSH/agent/persistence behaviour, not private
call sequences.

## 2. Use typed duplicate-serial retry

**Outcome.** One issuance retry path consumes R7's typed duplicate-serial
failure instead of matching text.

**Behavioural tests, in order:**

1. A forced collision retries and then successfully issues.
2. An unexpected persistence error has the same safe failure and does not retry.

**Implementation boundary.** Do not alter serial generation or exception text
presented to users.

## 3. Select one application issuance workflow

**Outcome.** Exactly one production service owns issuance ordering.

**Behavioural tests, in order:**

1. Route runtime success through the selected workflow and retain ordering.
2. Route one compensation branch through that same workflow.
3. Delete or make private the unused competing orchestration entry point.

**Implementation boundary.** Use narrow signer, agent, and recorder
collaborators; avoid a service locator.

## 4. Extract the AsyncSSH agent adapter

**Outcome.** AsyncSSH mechanics and issuer-ownership checks are an adapter;
the application workflow owns policy and state transitions.

**Behavioural tests, in order:**

1. Move one real agent add/owned-key removal operation while unrelated keys
   survive.
2. Move remaining agent operations while success and compensation tests remain
   green.
3. Exercise the workflow through an external agent boundary without mocking its
   own state machine.

**Implementation boundary.** Do not change forwarding requirements or delete
non-owned identities.

## 5. Represent cleanup and audit outcomes explicitly

**Outcome.** Internal cleanup/audit errors cannot be mistaken for successful
issuance, with no user-visible behaviour change.

**Behavioural tests, in order:**

1. A cleanup failure is an internal failed outcome and retains safe session
   output.
2. A failure-event write problem is distinct from successful durable issuance.
3. Normal success has no failure outcome.

**Implementation boundary.** Do not add operator events or new output in this
refactor.
