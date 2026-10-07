"""Offline transition tests for the HTTP snapshot normalization boundary."""
from copy import deepcopy
from http_snapshot_consumer import reconcile_snapshot


BASE = {
    "schemaVersion": "0.3",
    "snapshotId": "sim-1",
    "asOf": "2026-10-07T00:00:00Z",
    "source": {"system": "Pasarela-de-pago-AMR", "environment": "simulation"},
    "liabilities": {"walletBalanceMinor": 1000000, "currency": "MXN", "walletCount": 2},
    "settlementEvidence": {
        "eligibleSettledMinor": 1000000,
        "encumberedMinor": 0,
        "currency": "MXN",
        "verificationStatus": "VERIFIED",
        "evidenceRefs": [{"kind": "stripe_settlement", "reference": "simulation", "hash": "abc"}],
    },
    "integrity": {"ledgerHash": "abc", "generatedBy": "test"},
}


def run():
    simulation = reconcile_snapshot(BASE)
    assert simulation["state"] == "FULLY_BACKED"
    assert simulation["new_conversion_allowed"] is True

    production = deepcopy(BASE)
    production["source"]["environment"] = "production"
    production["settlementEvidence"]["eligibleSettledMinor"] = 0
    production["settlementEvidence"]["verificationStatus"] = "PENDING"
    production["settlementEvidence"]["evidenceRefs"] = [
        {"kind": "custody_attestation", "reference": "missing_production_evidence", "hash": "def"}
    ]
    production["integrity"]["ledgerHash"] = "def"

    blocked = reconcile_snapshot(production)
    assert blocked["state"] == "BACKING_PENDING"
    assert blocked["eligible_liquid_mxn"] == 0
    assert blocked["new_conversion_allowed"] is False
    assert blocked["max_additional_convertible_mxn"] == 0
    return {"simulation": simulation, "production_without_external_evidence": blocked}


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2))
