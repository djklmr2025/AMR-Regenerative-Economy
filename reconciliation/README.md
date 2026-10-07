# Treasury Reconciliation

This module compares verified liquid MXN evidence with AMR-FIAT liabilities.

It is intentionally pure/offline in v0.3:
- no Stripe API;
- no banking API;
- no MongoDB;
- no wallet keys;
- no mint/burn;
- no transfer execution.

External systems must first normalize their evidence into the v0.3 snapshot schemas. Only independently verified eligible liquid MXN counts as fiat backing.

AMR-IO production proofs may be analyzed alongside reconciliation reports, but production value is never silently promoted to fiat reserves.
