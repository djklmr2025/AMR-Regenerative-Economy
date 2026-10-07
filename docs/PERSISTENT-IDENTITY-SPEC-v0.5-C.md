# AMR Persistent Sovereign Identity Spec v0.5-C

## 1. Purpose

AMR v0.5-C makes the v0.5-B sovereign identity state durable across process restarts for local/single-node deployments.

The reference backend is SQLite. This specification does **not** claim distributed or multi-instance identity consensus.

v0.5-C preserves the v0.5-B security boundary:

```text
agentId -> keyId -> public key + lifecycle state
        -> permissions/capabilities
        -> durable audit history

private key -> external keystore / KMS / HSM / vault
```

Private signing keys MUST NOT be persisted by the identity registry.

## 2. Security invariants

The persistent registry MUST preserve these invariants across restart:

1. `agentId` remains stable.
2. A `keyId` is globally unique and MUST NOT be rebound to different key material.
3. Revoked or rotated key identifiers remain retired permanently.
4. A `REVOKED` key MUST NOT authorize new operations.
5. A `ROTATED` key MUST NOT authorize new privileged operations.
6. Permissions are explicit and deny-by-default.
7. Identity administration is separate from ordinary agent authorization.
8. Registry/database failure results in fail-closed behavior.
9. Lifecycle mutations are atomic: partial rotation/revocation MUST NOT become visible.
10. Audit events and the state mutation they describe MUST commit atomically.
11. Private keys/secrets are absent from registry tables, serialized state, and audit events.
12. Memory/prompt content remains non-authoritative.
13. v0.5-A replay protection remains an independent mandatory control when request authorization is integrated.

## 3. Persistence model

The SQLite implementation SHOULD persist normalized records equivalent to:

### agents
- `agent_id` PRIMARY KEY
- `active`

### keys
- `key_id` PRIMARY KEY
- `agent_id` FOREIGN KEY
- `algorithm`
- public verification material
- `status`: ACTIVE / ROTATED / REVOKED
- `not_before`
- `not_after`
- `revoked_at`

### permissions
- `agent_id`
- `capability`
- UNIQUE(agent_id, capability)

### retired_key_ids
- `key_id` PRIMARY KEY
- retirement metadata sufficient to prevent identifier resurrection

### identity_audit
- append-only event identifier
- event type
- agent/key references
- event timestamp
- public metadata only

No table may contain a plaintext private signing key.

## 4. SQLite transaction rules

Lifecycle mutations MUST use explicit transactions.

Registration MUST atomically create the agent, initial public key, permissions, and audit event.

Rotation MUST atomically:
1. verify the old key is currently ACTIVE and bound to the agent;
2. reject a new `keyId` that has ever been used/retired;
3. mark the old key ROTATED;
4. tombstone the old `keyId`;
5. insert the new ACTIVE public key;
6. append the rotation audit event;
7. commit all changes together.

Revocation MUST atomically:
1. resolve the exact agent/key binding;
2. reject invalid lifecycle transitions;
3. mark the key REVOKED;
4. persist its revocation timestamp;
5. tombstone the `keyId`;
6. append the revocation audit event;
7. commit all changes together.

Any failure before commit MUST roll back the complete mutation.

## 5. Concurrency

SQLite mutations MUST be serialized by database transaction semantics, not only by Python thread locks.

Two processes racing to rotate the same ACTIVE key MUST NOT both succeed.

Exactly one valid conflicting mutation may commit; the loser MUST observe the changed state and fail closed.

A SELECT-before-INSERT pattern without transactional protection is insufficient.

Busy/locked/indeterminate database errors MUST NOT be interpreted as ordinary authorization success or as proof that an operation completed.

## 6. Restart semantics

Closing and reopening the registry MUST preserve:
- agents;
- public keys;
- permissions;
- ACTIVE/ROTATED/REVOKED state;
- tombstones;
- audit history.

A restart MUST NOT reactivate a revoked/rotated credential or permit reuse of a retired `keyId`.

## 7. Corruption and outage semantics

If the registry cannot reliably establish current identity/key/permission state, protected operations MUST fail closed.

Database exceptions MUST be surfaced internally as identity-registry errors, not silently converted into permission grants.

The implementation MUST NOT automatically rebuild an empty authoritative registry after detecting an existing but unreadable/corrupt database.

Recovery from corruption is an explicit administrative procedure outside the normal authorization path.

## 8. Private-key custody

The persistent registry stores public verification material only.

Production private keys belong in an external controlled signer such as an OS keystore, KMS, HSM, secrets manager, or equivalent signing service.

The registry MUST NOT offer an API to export private signing keys because it never owns them.

## 9. Audit history

Security-relevant lifecycle changes MUST create durable audit events.

At minimum:
- AGENT_REGISTERED
- KEY_ROTATED
- KEY_REVOKED
- PERMISSION_GRANTED / permission changes introduced by implementation

Audit history SHOULD be append-only through the application API.

Audit events MUST NOT contain private keys, passwords, bearer tokens, or unrelated memory/prompt content.

## 10. Replay + Identity integration invariant

When v0.5-C is integrated with authenticated requests, the controls remain separate:

1. parse/validate request structure;
2. resolve trusted identity and current key state;
3. cryptographically verify the signature;
4. authorize the requested capability;
5. enforce freshness;
6. atomically consume the replay identifier;
7. execute the protected operation.

A failed signature MUST NOT burn a replay identifier.

A revoked/rotated/unauthorized credential MUST NOT burn a replay identifier.

A replayed request MUST remain rejected even when its identity and signature are otherwise valid.

The final integration audit MUST rerun the v0.5-A guarantees rather than assuming they survived integration.

## 11. Threat model additions

v0.5-C adds persistence-specific threats to the v0.5-B model:

### C1 — Restart resurrection
A revoked/rotated credential becomes ACTIVE after process restart.

Expected: reject.

### C2 — Tombstone loss
A retired `keyId` is reused after restart.

Expected: reject.

### C3 — Partial rotation
A crash/error occurs between retiring the old key and installing the new key.

Expected: atomic rollback or complete commit; never a partially committed identity transition.

### C4 — Concurrent process rotation
Two independent registry instances/processes rotate the same key.

Expected: exactly one conflicting rotation succeeds.

### C5 — Audit/state split
State changes commit but the corresponding lifecycle audit event does not, or vice versa.

Expected: impossible through the supported mutation API because both share one transaction.

### C6 — Database outage/lock
SQLite cannot complete an authoritative read or write.

Expected: fail closed.

### C7 — Corrupt database fallback
An unreadable existing DB is treated as an empty fresh registry.

Expected: forbidden; fail closed.

### C8 — Secret persistence
Private signing material reaches SQLite or lifecycle logs.

Expected: forbidden and tested.

## 12. Destructive audit gate

`audit_v05_persistent_identity.py` MUST test at least:

- registration survives close/reopen;
- permissions survive close/reopen;
- rotated old key remains rejected after reopen;
- new rotated key remains ACTIVE after reopen;
- revoked key remains rejected after reopen;
- retired/revoked `keyId` reuse fails after reopen;
- lifecycle audit events survive reopen;
- no private-key field/material is persisted;
- failed rotation rolls back completely;
- database failure/corruption fails closed;
- two independent registry instances racing the same rotation yield exactly one winner;
- memory/prompt claims still cannot mutate authority;
- identity administrative mutation remains separately authorized;
- existing v0.5-B authorization semantics remain valid;
- integrated Replay + Identity tests preserve v0.5-A burn/replay guarantees.

The auditor MUST exit nonzero on any failed assertion.

## 13. Acceptance gate

v0.5-C receives PASS only after:
1. implementation review;
2. destructive persistence audit;
3. restart tests;
4. concurrency test using independent SQLite connections/registry instances;
5. rollback/failure tests;
6. clean process exit code 0;
7. no committed or persisted private signing keys;
8. regression verification for v0.5-B;
9. Replay + Identity integration regression for v0.5-A.

## 14. Explicit scope limitation

A passing SQLite implementation demonstrates durable local/single-node identity semantics.

It does **not** demonstrate:
- distributed consensus;
- cross-region consistency;
- multi-primary identity mutation safety;
- HSM-grade key custody;
- Byzantine fault tolerance.

Those require separate architecture and evidence.
