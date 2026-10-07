# AMR v0.3 — Fiat Bridge & Treasury Reconciliation

## Status
Specification-first design. No real funds, minting, redemption, or payment execution is enabled by this document.

## Monetary domains
AMR separates two accounting domains:

- **AMR-IO** — internal utility/accounting units used by the agent economy. AMR-IO is not automatically redeemable for MXN.
- **AMR-FIAT** — a convertible liability that may be issued only when matched by eligible, independently verified liquid MXN reserves.

Conversion between the domains is a controlled Level-4 action.

## Backing equation

Let:

- `L` = eligible verified liquid MXN reserves.
- `C` = outstanding AMR-FIAT convertible liabilities denominated in MXN.
- `R` = MXN-denominated restricted redemption/settlement obligations that must remain liquid.
- `H` = prudential haircut/buffer required by policy.

A fully backed state requires:

```
L >= C + R + H
```

Coverage ratio:

```
coverage_ratio = L / (C + R + H)
```

when the denominator is non-zero.

**Important:** the ecosystem's general emergency reserve must not be double-counted as a fiat backing liability. Only obligations that contractually require liquid MXN belong in `R`.

## Asset eligibility
An asset counts toward `L` only if its evidence establishes:
1. ownership or enforceable economic right;
2. custodian/account;
3. MXN denomination or approved liquid conversion basis;
4. valuation timestamp;
5. encumbrances;
6. independent verification status;
7. no double counting in another backing pool.

Regenerative production, IP, compute, equipment, land, commodities, or expected revenue can strengthen ecosystem net worth but **do not count as liquid MXN backing** unless converted into eligible liquid reserves.

## State machine
- `INTERNAL_ONLY`: AMR-IO exists; no fiat convertibility claim.
- `BACKING_PENDING`: reserve evidence exists but is not fully verified.
- `FULLY_BACKED`: verified equation passes.
- `DEFICIT`: eligible reserves are below required liabilities/buffer.
- `FROZEN`: conversion issuance is disabled by policy or audit.

Only `FULLY_BACKED` permits creation of new AMR-FIAT liabilities, and only up to the verified headroom.

## Reconciliation invariant
The reconciler is observational and policy-enforcing. It must never fabricate reserves, infer bank balances from AMR balances, or treat a payment-provider success redirect as reserve evidence.

Production proofs and reserve proofs remain separate ledgers. Production can create economic surplus; only realized eligible MXN can enter the fiat backing pool.

## Integration boundary
The existing Pasarela-de-pago-AMR is treated as an external adapter. v0.3 consumes normalized evidence snapshots; it does not receive payment credentials, wallet keys, Stripe secrets, database credentials, or authority to move funds.

## Failure behavior
On stale evidence, conflicting evidence, deficit, or audit failure:
- block new AMR-FIAT issuance/conversion;
- preserve AMR-IO internal accounting;
- do not erase agent balances;
- generate an auditable reconciliation result;
- require Level-4 human/multi-authorization before corrective treasury actions.
