# R7 — Central domain policy and typed domain failures

## Scope

Give security-relevant grammar, certificate policy, and expected persistence
conflicts one authoritative definition. All untrusted and persisted boundaries
continue to validate data even after sharing the policy.

## 1. Characterize existing policy at public boundaries

**Outcome.** Existing observable acceptance and rejection semantics are pinned
before policy moves.

**Behavioural tests, in order:**

1. CLI and SSH-facing tests characterize canonical username, group, and
principal acceptance and rejection edges.
2. Public issuance/state tests characterize serial bounds, 25-hour validity,
and allowed certificate extensions.
3. A duplicate serial observed through the public issuance boundary remains a
safe failure rather than a leaked SQLite message.

**Implementation boundary.** Add only characterization tests. Do not alter
grammar, lifetime, extensions, output, or exception translation.

**Done when.** The behaviour that later policy extraction must preserve is
visible through public interfaces.

## 2. Canonical identity and principal policy

**Outcome.** Identity, group, and principal grammar has one domain-level
source while every boundary continues to reject invalid input.

**Behavioural tests, in order:**

1. Move one canonical username validation consumer to the domain policy and
prove its CLI-visible accept/reject result is unchanged.
2. Migrate group and principal consumers one at a time, retaining persistence
validation for corrupted rows.
3. Add a focused architecture test which rejects duplicate production
definitions of the canonical policy.

**Implementation boundary.** Prefer small validated functions/records. Do not
introduce a generic utility module or weaken database validation.

**Done when.** One policy source serves all consumers and malformed external or
persisted values still fail closed.

## 3. Ordinary certificate lifetime and extension policy

**Outcome.** Configuration, signing, and persistence validate the same
ordinary-certificate policy.

**Behavioural tests, in order:**

1. A configured ordinary issuance still produces exactly a 25-hour certificate
with the existing principals and extensions.
2. Migrate signing and persistence validation to one policy value without
changing the emitted certificate.
3. The architecture test rejects duplicate core certificate-lifetime or
extension-policy definitions in production code.

**Implementation boundary.** Keep the existing configured semantics; this is
not authorization-policy redesign.

**Done when.** There is one authoritative ordinary certificate policy and
existing output remains byte/semantics-compatible where currently asserted.

## 4. Typed expected persistence conflicts

**Outcome.** Application control flow recognizes duplicate serials through a
typed persistence failure, never exception-message matching.

**Behavioural tests, in order:**

1. A duplicate serial from the public persistence boundary produces a specific
safe domain failure.
2. Migrate one issuance retry path and prove retry/success behaviour is
unchanged.
3. Migrate remaining expected conflict consumers and ensure unexpected storage
failures still receive safe outer translation.

**Implementation boundary.** Define only expected control-flow errors; do not
wrap every exception or expose SQLite details.

**Done when.** No production issuance path branches on human-readable database
error text.
