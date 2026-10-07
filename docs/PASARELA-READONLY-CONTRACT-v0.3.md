# Pasarela Read-Only Evidence Contract v0.3

## Repository review
The current Pasarela implementation keeps authenticated fiat-derived balances in `fiat_wallets`, checkout state in `fiat_checkouts`, and idempotent credits in `fiat_credits`. A paid Stripe session is validated and then credits the wallet transactionally.

That is useful evidence of **AMR liabilities**, but it is not by itself proof that equivalent MXN remains liquid and redeemable.

## Critical accounting distinction

```
sum(fiat_wallets.balanceMinor)
        = user-facing AMR liability candidate

Stripe checkout / fiat_credits
        = provenance that a credit event occurred

Stripe/bank/custody settlement evidence
        = candidate proof of liquid MXN reserves
```

A successful checkout, `PAID` state, `fiat_credits` record, or wallet balance MUST NOT be counted as a cash reserve.

## Read-only export
The bridge accepts one evidence envelope conforming to `schemas/pasarela-readonly-evidence.schema.json`.

The exporter may read:
- aggregate authenticated wallet balances;
- wallet count;
- reconciled settlement evidence;
- encumbrances;
- timestamps and integrity hashes.

The exporter must never expose:
- Firebase ID tokens;
- Stripe API/webhook secrets;
- MongoDB credentials;
- user email/NIP/password;
- wallet private keys/seeds;
- raw payment credentials.

No per-user PII is needed for treasury reconciliation.

## Liability rule
For the current authenticated fiat-wallet subsystem, the conservative liability candidate is:

```
convertible_liability_mxn =
    SUM(fiat_wallets.balanceMinor) / 100
```

This becomes AMR-FIAT only after policy explicitly classifies those balances as redeemable. Until then they remain internal liabilities/credits and must not be advertised as guaranteed MXN redemption.

## Reserve rule
`eligibleSettledMinor` MUST originate from independently reconcilable settlement/custody evidence. It must not be computed from `fiat_wallets`, `fiat_credits`, checkout totals, AMR production, or legacy wallet balances.

```
eligible_liquid_mxn =
  (eligibleSettledMinor - encumberedMinor) / 100
```

Only `verificationStatus=VERIFIED` can be presented to the reconciler as verified liquidity.

## Read-only endpoint proposal
Future Pasarela endpoint:

`GET /api/internal/reconciliation/v1/snapshot`

Properties:
- service-to-service read-only authorization;
- no mutation capability;
- aggregate values only;
- short-lived request authentication;
- replay protection;
- rate limiting;
- timestamp/freshness limit;
- response hash/signature;
- audit log for each export.

The AMR reconciler should have a credential capable of calling this endpoint and **nothing else**.

## Fail-closed rules
Reject the snapshot if:
- schema validation fails;
- timestamp is stale;
- currency is not MXN;
- encumbrances exceed eligible settlement;
- integrity verification fails;
- settlement evidence is absent;
- verification is not VERIFIED for conversion purposes;
- liability and reserve snapshots refer to incompatible reconciliation periods.

## Known boundary
The current Pasarela code proves transactional crediting of authenticated AMR balances. It does **not**, from the application ledger alone, prove the current cash/custody balance held outside the application. Production integration therefore requires an independent settlement/custody evidence source before AMR-FIAT convertibility can be enabled.
