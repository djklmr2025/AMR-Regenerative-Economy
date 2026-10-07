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
    import unittest
    from unittest.mock import patch
    from urllib.error import HTTPError
    from pasarela_adapter import EvidenceError
    from http_snapshot_consumer import fetch_snapshot, SnapshotTransportError

    print("--- TRANSITION TESTS ---")
    print(json.dumps(run(), indent=2))

    class TestAttacks(unittest.TestCase):
        def test_wrong_currency(self):
            bad = deepcopy(BASE)
            bad["liabilities"]["currency"] = "USD"
            with self.assertRaisesRegex(EvidenceError, "currency must be MXN"):
                reconcile_snapshot(bad)

        def test_negative_value(self):
            bad = deepcopy(BASE)
            bad["liabilities"]["walletBalanceMinor"] = -100
            with self.assertRaisesRegex(EvidenceError, "must be a non-negative integer"):
                reconcile_snapshot(bad)

        def test_boolean_value(self):
            bad = deepcopy(BASE)
            bad["settlementEvidence"]["eligibleSettledMinor"] = True
            with self.assertRaisesRegex(EvidenceError, "must be a non-negative integer"):
                reconcile_snapshot(bad)

        def test_wrong_schema(self):
            bad = deepcopy(BASE)
            bad["schemaVersion"] = "0.2"
            with self.assertRaisesRegex(EvidenceError, "unsupported schemaVersion"):
                reconcile_snapshot(bad)

        def test_incomplete_json(self):
            bad = deepcopy(BASE)
            del bad["liabilities"]
            with self.assertRaisesRegex(EvidenceError, "malformed snapshot"):
                reconcile_snapshot(bad)

        def test_verification_status_bypass(self):
            bad = deepcopy(BASE)
            bad["settlementEvidence"]["verificationStatus"] = "PENDING"
            self.assertFalse(reconcile_snapshot(bad)["new_conversion_allowed"])

            bad["settlementEvidence"]["verificationStatus"] = "REJECTED"
            self.assertFalse(reconcile_snapshot(bad)["new_conversion_allowed"])

            bad["settlementEvidence"]["verificationStatus"] = "HACKED"
            with self.assertRaisesRegex(EvidenceError, "invalid verificationStatus"):
                reconcile_snapshot(bad)

        @patch("http_snapshot_consumer.urlopen")
        def test_http_401(self, mock_urlopen):
            mock_urlopen.side_effect = HTTPError("url", 401, "Unauthorized", {}, None)
            with self.assertRaisesRegex(SnapshotTransportError, "snapshot fetch failed closed"):
                fetch_snapshot("https://pasarela.test", "secret")

        @patch("http_snapshot_consumer.urlopen")
        def test_timeout(self, mock_urlopen):
            mock_urlopen.side_effect = TimeoutError("timeout")
            with self.assertRaisesRegex(SnapshotTransportError, "snapshot fetch failed closed"):
                fetch_snapshot("https://pasarela.test", "secret")

        def test_no_https(self):
            with self.assertRaisesRegex(SnapshotTransportError, "HTTPS is required"):
                fetch_snapshot("http://pasarela.test", "secret")

    print("\n--- RUNNING ATTACKS ---")
    suite = unittest.TestLoader().loadTestsFromTestCase(TestAttacks)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
