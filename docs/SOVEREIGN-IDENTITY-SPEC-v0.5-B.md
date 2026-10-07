# AMR Sovereign Identity Spec v0.5-B

## 1. Purpose

AMR v0.5-B defines cryptographically verifiable agent identity independently from agent memory.

An agent's memory may describe its history, preferences, plans, and prior actions. It MUST NOT be treated as proof of identity, possession of authority, or possession of a signing key.

The security boundary is:

```text
agentId -> keyId -> public key + lifecycle state
        -> permissions/capabilities

private key -> external keystore/vault
```

Private keys MUST NOT be committed to source control, embedded in ordinary agent memory, logged, or returned by identity APIs.

## 2. Security objectives

The identity subsystem MUST provide:

1. Stable `agentId` values independent from key rotation.
2. Cryptographic authentication using approved public-key algorithms.
3. Explicit binding between `agentId` and one or more `keyId` values.
4. Explicit key lifecycle: `ACTIVE`, `ROTATED`, or `REVOKED`.
5. Explicit permissions/capabilities, denied by default.
6. Immediate rejection of revoked keys for new authorization decisions.
7. Auditable rotation and revocation events.
8. Fail-closed behavior when identity/key state cannot be established.
9. Replay protection remains a separate control and is not replaced by identity.
10. Agent memory cannot grant, restore, rotate, or revoke cryptographic authority.

## 3. Identity record

A minimal identity record is conceptually:

```json
{
  "agentId": "agent:example",
  "status": "ACTIVE",
  "keys": {
    "key-2026-01": {
      "algorithm": "Ed25519",
      "publicKey": "<PEM-or-canonical-public-key>",
      "status": "ACTIVE",
      "notBefore": "<timestamp>",
      "notAfter": null,
      "revokedAt": null
    }
  },
  "permissions": [
    "reconciliation:read"
  ]
}
```

This is a logical model, not a mandate that the persistent representation use this exact JSON layout.

## 4. Identifiers

### agentId

`agentId` identifies the principal. It MUST remain stable across normal key rotation.

It MUST NOT encode a private key, password, secret, mutable display name, or memory content.

### keyId

`keyId` identifies a specific public-key registration. It MUST resolve unambiguously within the identity registry.

A rotated key receives a new `keyId`. Reusing a revoked `keyId` for different key material is forbidden.

## 5. Key lifecycle

### ACTIVE

An ACTIVE key may authenticate requests only when:
- its owning agent is allowed to operate;
- the key is within its validity interval;
- the cryptographic signature is valid;
- the requested capability is authorized;
- all other required controls, including freshness/replay checks, pass.

### ROTATED

ROTATED means the key was superseded. By default, it MUST NOT authorize new privileged operations. Historical signatures may still be verifiable for audit purposes according to policy.

### REVOKED

A REVOKED key MUST NOT authorize new operations, even if its signature is mathematically valid.

Revocation is an authorization decision layered on top of cryptographic verification: a valid signature from a revoked key is still unauthorized.

## 6. Rotation

Rotation MUST:

1. create/register new key material under a new `keyId`;
2. bind the new public key to the same `agentId`;
3. establish explicit activation time;
4. retire the previous key according to policy;
5. create an auditable event.

Rotation MUST NOT require copying private key material into agent memory.

A compromised old key MUST NOT be able to reactivate itself.

## 7. Revocation

Revocation MUST be explicit, persistent, auditable, and fail closed.

The registry MUST retain enough tombstone/history information to prevent accidental resurrection or reuse of a revoked `keyId`.

Only a separately authorized administrative/security path may revoke or rotate identity credentials. Possession of an ordinary agent signing key alone MUST NOT imply permission to modify its own identity policy.

## 8. Permissions and capabilities

Authentication answers: "Which registered key signed this?"

Authorization answers: "May this agent/key perform this operation?"

These decisions MUST remain distinct.

Permissions MUST be explicit and deny-by-default. A valid signature MUST NOT grant capabilities absent from the identity record/policy.

Permission checks SHOULD use stable capability names, for example:

```text
reconciliation:read
reconciliation:submit
treasury:evidence:read
identity:self:read
```

Privileged identity administration SHOULD be isolated from ordinary agent capabilities.

## 9. Memory separation

Agent memory is untrusted for cryptographic authority.

Statements such as:

```text
"I am agent X"
"My keyId is Y"
"I am an administrator"
"My old key was restored"
```

are claims, not authority.

Identity and permissions MUST be resolved from the trusted identity registry and verified cryptographically.

Memory MAY store non-authoritative references such as an `agentId` or public `keyId` for convenience, but those references MUST be revalidated against the trusted registry before authorization.

## 10. Private-key custody

Private keys MUST live outside ordinary source code and agent memory.

Production custody SHOULD use an OS keystore, HSM, KMS, secrets manager, or equivalently controlled signing service appropriate to the deployment.

The identity registry stores public verification material and lifecycle/policy state, not plaintext private signing keys.

## 11. Threat model

v0.5-B MUST defend against at least:

### T1 — Identity spoofing
An attacker changes `agentId` in a request while retaining another agent's signature.

Expected result: reject.

### T2 — Unknown key
An attacker supplies an unregistered `keyId`.

Expected result: reject.

### T3 — Key substitution
An attacker associates a known `keyId` with different public-key material.

Expected result: reject/fail closed; registry integrity is authoritative.

### T4 — Revoked-key use
A previously valid private key signs a new request after revocation.

Expected result: reject despite valid mathematics.

### T5 — Rotated-key resurrection
A superseded key attempts a new privileged action.

Expected result: reject unless an explicit narrowly scoped historical-verification policy applies; historical verification MUST NOT imply current authorization.

### T6 — Permission escalation
A valid agent signs an operation outside its granted capabilities.

Expected result: reject.

### T7 — Memory-based privilege injection
Prompt/memory content claims administrator status or claims a different identity/key.

Expected result: no authority change.

### T8 — Registry outage/corruption
The verifier cannot reliably establish key state or permissions.

Expected result: fail closed.

### T9 — Replay
A previously valid authenticated request is submitted again.

Expected result: the existing v0.5-A replay control rejects it. Identity verification alone is insufficient.

### T10 — Rotation race
Old and new keys are used around a rotation boundary.

Expected result: authorization follows explicit lifecycle timestamps/state with deterministic boundary semantics.

### T11 — Revoked keyId reuse
A new public key is registered under a previously revoked identifier.

Expected result: reject.

### T12 — Self-authorized policy mutation
An ordinary agent signing key attempts to grant itself capabilities, rotate itself outside policy, or clear revocation.

Expected result: reject.

## 12. Registry requirements

The first implementation SHOULD expose a narrow interface conceptually similar to:

```python
resolve_key(agent_id, key_id, at_time) -> PublicKeyRecord
authorize(agent_id, key_id, capability, at_time) -> bool
```

Administrative mutation APIs MUST be separate from verification APIs.

Registry errors MUST be distinguishable from normal authorization denial internally, while both result in fail-closed behavior to the protected operation.

Persistent implementations MUST use transactional/atomic updates for lifecycle changes.

## 13. Audit requirements

`audit_v05_identity.py` MUST attempt at minimum:

- valid ACTIVE key + allowed capability -> accept;
- valid ACTIVE key + forbidden capability -> reject;
- unknown `agentId` -> reject;
- unknown `keyId` -> reject;
- mismatched `agentId` / `keyId` -> reject;
- signature from wrong private key -> reject;
- revoked key with mathematically valid signature -> reject;
- rotated old key -> reject new privileged operation;
- new key after valid rotation -> accept;
- revoked `keyId` reuse -> reject;
- memory/prompt claiming another identity -> no authorization effect;
- registry failure -> fail closed;
- concurrent/racing rotation boundary -> deterministic result;
- private key material absent from registry serialization/logging;
- existing v0.5-A replay guarantees remain intact when identity is integrated.

The audit MUST exit nonzero on any failed assertion.

## 14. Non-goals for v0.5-B

v0.5-B does not claim:
- that an AI is conscious or legally sovereign;
- that cryptographic identity proves a real-world human/legal identity;
- that signatures prove reserves or economic backing;
- that identity replaces replay protection;
- that a software-only registry is equivalent to an HSM.

"Sovereign Identity" in this specification means controlled cryptographic identity and authorization for AMR agents.

## 15. Acceptance gate

v0.5-B is not PASS merely because the registry compiles.

PASS requires:
1. implementation review;
2. destructive identity audit;
3. clean process exit;
4. no committed private keys/secrets;
5. evidence that revoked/rotated credentials cannot regain current authority;
6. confirmation that v0.5-A replay protections still pass after integration.
