# HTTP Snapshot Consumer v0.3

The consumer performs exactly one remote operation: an HTTPS GET of the Pasarela reconciliation snapshot. It has no POST/PUT/PATCH/DELETE implementation and receives a read-only credential at runtime.

Flow:

```
Pasarela GET snapshot -> normalize integer minor units -> ReserveSnapshot + LiabilitySnapshot -> reconcile()
```

The consumer rejects malformed/negative monetary values, non-MXN snapshots, unsupported schema versions and missing integrity identifiers. A non-VERIFIED reserve status contributes zero eligible liquidity through the reconciler.

## Critical transition test

The offline test models the same liabilities twice:

1. `simulation`: 10,000 MXN liability and 10,000 MXN simulated VERIFIED settlement -> `FULLY_BACKED`.
2. `production`: same liability, zero external evidence and `PENDING` -> `BACKING_PENDING`, conversion disabled, zero issuance headroom.

This is deliberately not a live-money test.
