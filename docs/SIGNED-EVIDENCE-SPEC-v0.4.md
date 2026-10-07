# Signed Evidence Specification (v0.4)

## Abstract
This specification defines the security boundary for transmitting reconciliation snapshots from the fiat environment (Pasarela) to the decentralized ledger environment (AMR). It upgrades the v0.3 HTTP snapshot consumer by introducing cryptographic asymmetric signatures, effectively rendering the snapshot immutable and irrefutable in transit, without requiring the consumer to hold any secrets capable of forging evidence.

## Threat Model & Mitigations
| Threat | Description | Mitigation |
|--------|-------------|------------|
| **Data Tampering** | An attacker intercepts the HTTP response and modifies the `eligibleSettledMinor` to artificially inflate the backup. | The payload is signed with Pasarela's private key. The signature becomes invalid if a single byte is changed. |
| **Identity Spoofing** | An attacker stands up a rogue endpoint that returns a perfectly formed JSON snapshot. | The consumer verifies the signature against a pre-authorized public key (`keyId`). |
| **Replay Attacks** | An attacker captures a valid, highly-collateralized snapshot from yesterday and replays it today during a deficit. | The consumer enforces a **freshness window** (e.g., `asOf` must be within the last 5 minutes) and can track `snapshotId`s to prevent duplicate ingestion. |

## Cryptographic Design (Asymmetric)
* **Algorithm**: `EdDSA` (Ed25519) or `RSASSA-PKCS1-v1_5` (RSA-2048+) or `ECDSA` (P-256). Ed25519 is recommended for its speed and short signature length.
* **Key Management**:
  * **Pasarela (Issuer)**: Holds the private key. Signs the snapshot.
  * **AMR Reconciler (Consumer)**: Holds the public key. Verifies the snapshot.
* **Signature Target**: The signature is computed over a strictly defined, multiline UTF-8 string with `\n` line endings, protecting all critical context:

```text
AMR-SNAPSHOT-SIG-V1
schemaVersion={schemaVersion}
snapshotId={snapshotId}
asOf={asOf}
system={system}
environment={environment}
walletBalanceMinor={walletBalanceMinor}
walletCount={walletCount}
liabilityCurrency={liabilityCurrency}
eligibleSettledMinor={eligibleSettledMinor}
encumberedMinor={encumberedMinor}
settlementCurrency={settlementCurrency}
verificationStatus={verificationStatus}
ledgerHash={ledgerHash}
keyId={keyId}
```

## Schema Changes (schemaVersion: "0.4")
The `integrity` object is expanded to include the asymmetric signature.

```json
{
  "schemaVersion": "0.4",
  "snapshotId": "snap-20261007-123456",
  "asOf": "2026-10-07T12:00:00Z",
  "source": { "...": "..." },
  "liabilities": { "...": "..." },
  "settlementEvidence": { "...": "..." },
  "integrity": {
    "ledgerHash": "sha256-hash-of-database-state",
    "signature": "base64-encoded-signature",
    "keyId": "pasarela-prod-key-v1"
  }
}
```

## Consumer Validation Rules
When the AMR HTTP Consumer receives a v0.4 snapshot, it MUST:
1. **Verify Schema**: `schemaVersion` must be `0.4`.
2. **Verify Freshness**: `abs(now() - asOf) <= 300` seconds (5 minutes).
3. **Verify Replay Protection**: Check that `snapshotId` has not been ingested within the freshness window (reject duplicates).
4. **Verify `keyId`**: The `keyId` must match an allowed, known public key.
5. **Verify Signature**: Construct the multiline `AMR-SNAPSHOT-SIG-V1` payload using exact UTF-8 and `\n` separators. Verify `integrity.signature` using the public key associated with `keyId`.
6. Proceed with v0.3 logic (fail-closed transition to `BACKING_PENDING` if production lacks evidence, etc.).
