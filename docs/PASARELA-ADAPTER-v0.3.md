# Pasarela Adapter v0.3

## Purpose
Translate **already exported evidence** from Pasarela-de-pago-AMR into the narrow snapshot types accepted by the AMR reconciler.

This is not a payment integration yet.

## Trust boundary

```
Pasarela evidence export
        |
        v
pasarela_adapter.py
        |
        +--> ReserveSnapshot
AMR ledger export
        |
        +--> LiabilitySnapshot
                  |
                  v
             reconciler.py
                  |
                  v
 FULLY_BACKED / DEFICIT / BACKING_PENDING
```

The adapter has no network client and receives no credentials.

## Eligible reserve input
For the simulated adapter, reserve evidence must identify:
- MXN currency;
- settled MXN;
- encumbered MXN;
- audit status;
- evidence URI;
- evidence timestamp.

Only `settled_mxn - encumbered_mxn` can become eligible liquidity, and only a `VERIFIED` audit status makes that liquidity usable by the reconciler.

## Explicit exclusions
These do **not** become liquid backing:
- pending Stripe Checkout Sessions;
- browser success redirects;
- uncredited payment intents;
- legacy/demo wallet balances;
- AMR-IO internal balances;
- regenerative production valuation;
- equipment, land, IP or expected revenue.

## Liability input
The AMR ledger export supplies AMR-FIAT convertible liabilities, restricted settlement obligations, prudential buffer and a ledger hash.

## Next production boundary
A later adapter may read authenticated, reconciled data from Pasarela-de-pago-AMR. That adapter must remain read-only and must prove freshness, provenance and idempotency before its output is accepted. Payment execution and treasury movement remain outside the reconciler.
