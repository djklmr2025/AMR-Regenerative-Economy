# AMR Sovereign Security Spec v0.5

## Introduction
AMR v0.5 moves from in-memory, session-bound replay verification to a persistent multi-control security model.

## v0.5-A: Persistent Replay Store
The v0.4 `seen_snapshots` set is replaced by a `ReplayStore` interface.

- Consumption of a `snapshotId` MUST be atomic.
- Ed25519 authentication MUST complete before replay consumption to prevent burn attacks.
- A replay-store outage or indeterminate result MUST fail closed.
- `SQLiteReplayStore` is intended for local/single-node durable deployments.
- `RedisReplayStore` is intended for horizontal scaling and MUST use atomic SET NX semantics with expiry.
- Replay state MUST survive process restarts for the required retention window.

### Asymmetric freshness
At verification time:
- maximum past age: 300 seconds;
- maximum future clock skew: 30 seconds;
- replay retention SHOULD extend until at least `asOf + 300s`;
- pruning MUST NOT make a still-valid authenticated snapshot replayable.

## v0.5-B: Sovereign Identity
Agent identity (`agentId`, public keys, `keyId`, permissions, rotation and revocation state) is separate from agent memory. Memory may record history and decisions; it is not cryptographic authority. Private signing keys MUST NOT be stored as ordinary agent memory or committed to source control.

## v0.5-C: Selective PRIMORDIAL Migration
Concepts from `PRIMORDIAL-VAULT` may be migrated only when tied to a concrete threat model and backed by tests. Existing PRIMORDIAL implementation code and exposed credentials are untrusted inputs and MUST NOT be imported wholesale.

## Audit requirements
`audit_v05.py` MUST test:
- persistence across store close/reopen;
- concurrent consumption where exactly one contender succeeds;
- authenticated replay rejection;
- burn-attack resistance;
- asymmetric freshness (-300s / +30s);
- fail-closed behavior on replay-store failure;
- unknown/wrong keys and signature tampering;
- identity rotation/revocation once v0.5-B is introduced.

Multi-instance production deployments MUST use a durable shared replay backend.
