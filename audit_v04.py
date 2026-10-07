import base64
import json
import time
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from reconciliation.http_snapshot_consumer import normalize_snapshot, EvidenceError


def generate_keypair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, pub_pem.decode("utf-8")


def create_and_sign_snapshot(private_key, pub_key_id, overrides=None):
    now_dt = datetime.now(timezone.utc)
    as_of = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    snapshot = {
        "schemaVersion": "0.4",
        "snapshotId": f"snap-{time.time_ns()}",
        "asOf": as_of,
        "source": {
            "system": "Pasarela-de-pago-AMR",
            "environment": "production",
        },
        "liabilities": {
            "walletBalanceMinor": 100000,
            "walletCount": 5,
            "currency": "MXN",
        },
        "settlementEvidence": {
            "eligibleSettledMinor": 100000,
            "encumberedMinor": 0,
            "currency": "MXN",
            "verificationStatus": "VERIFIED",
        },
        "integrity": {
            "ledgerHash": "hash123",
            "keyId": pub_key_id,
        },
    }

    if overrides:
        for key, value in overrides.items():
            if key in snapshot and isinstance(snapshot[key], dict) and isinstance(value, dict):
                snapshot[key].update(value)
            else:
                snapshot[key] = value

    payload_lines = [
        "AMR-SNAPSHOT-SIG-V1",
        "schemaVersion=0.4",
        f"snapshotId={snapshot.get('snapshotId')}",
        f"asOf={snapshot.get('asOf')}",
        f"system={snapshot['source']['system']}",
        f"environment={snapshot['source']['environment']}",
        f"walletBalanceMinor={snapshot['liabilities']['walletBalanceMinor']}",
        f"walletCount={snapshot['liabilities'].get('walletCount', 0)}",
        f"liabilityCurrency={snapshot['liabilities']['currency']}",
        f"eligibleSettledMinor={snapshot['settlementEvidence']['eligibleSettledMinor']}",
        f"encumberedMinor={snapshot['settlementEvidence']['encumberedMinor']}",
        f"settlementCurrency={snapshot['settlementEvidence']['currency']}",
        f"verificationStatus={snapshot['settlementEvidence']['verificationStatus']}",
        f"ledgerHash={snapshot['integrity']['ledgerHash']}",
        f"keyId={snapshot['integrity']['keyId']}",
    ]
    payload_bytes = "\n".join(payload_lines).encode("utf-8")
    signature = private_key.sign(payload_bytes)
    snapshot["integrity"]["signature"] = base64.b64encode(signature).decode("utf-8")
    return snapshot


def expect_rejected(label, snapshot, trusted_keys, **kwargs):
    try:
        normalize_snapshot(snapshot, trusted_keys, seen_snapshots=set(), **kwargs)
        print(f"[FAIL] {label}")
        return False
    except EvidenceError:
        print(f"[PASS] {label}")
        return True


def run_tests():
    print("--- STARTING v0.4 AUDIT ---")
    failures = 0
    private_key, pub_pem = generate_keypair()
    trusted_keys = {"test-key-v1": pub_pem}

    valid_snap = create_and_sign_snapshot(private_key, "test-key-v1")
    try:
        normalize_snapshot(valid_snap, trusted_keys, seen_snapshots=set())
        print("[PASS] Valid v0.4 snapshot accepted.")
    except Exception as exc:
        print(f"[FAIL] Valid snapshot rejected: {exc}")
        failures += 1

    mutations = [
        ("Tampered snapshot (walletBalanceMinor) rejected correctly.", "liabilities", "walletBalanceMinor", 999999),
        ("Tampered snapshot (eligibleSettledMinor) rejected correctly.", "settlementEvidence", "eligibleSettledMinor", 999999),
        ("Tampered snapshot (encumberedMinor) rejected correctly.", "settlementEvidence", "encumberedMinor", 50000),
        ("Tampered snapshot (verificationStatus) rejected correctly.", "settlementEvidence", "verificationStatus", "PENDING"),
        ("Tampered snapshot (snapshotId) rejected correctly.", None, "snapshotId", "tampered-id"),
        ("Tampered snapshot (ledgerHash) rejected correctly.", "integrity", "ledgerHash", "hacked-hash"),
        ("Tampered snapshot (environment) rejected correctly.", "source", "environment", "sandbox"),
    ]
    for label, section, key, value in mutations:
        tampered = json.loads(json.dumps(valid_snap))
        if section:
            tampered[section][key] = value
        else:
            tampered[key] = value
        if not expect_rejected(label, tampered, trusted_keys):
            failures += 1

    snap_bad_sig = json.loads(json.dumps(valid_snap))
    snap_bad_sig["integrity"]["signature"] = "a" * 44
    if not expect_rejected("Corrupt signature Base64 rejected correctly.", snap_bad_sig, trusted_keys):
        failures += 1

    snap_unknown_key = json.loads(json.dumps(valid_snap))
    snap_unknown_key["integrity"]["keyId"] = "unknown-key"
    if not expect_rejected("Unknown keyId rejected correctly.", snap_unknown_key, trusted_keys):
        failures += 1

    _, wrong_pub_pem = generate_keypair()
    if not expect_rejected(
        "Wrong public key rejected correctly.",
        valid_snap,
        {"test-key-v1": wrong_pub_pem},
    ):
        failures += 1

    old_dt = datetime.fromtimestamp(time.time() - 301, timezone.utc)
    old_snap = create_and_sign_snapshot(
        private_key,
        "test-key-v1",
        overrides={"asOf": old_dt.strftime("%Y-%m-%dT%H:%M:%SZ")},
    )
    if not expect_rejected("Stale snapshot (> 300s) rejected correctly.", old_snap, trusted_keys):
        failures += 1

    future_dt = datetime.fromtimestamp(time.time() + 301, timezone.utc)
    future_snap = create_and_sign_snapshot(
        private_key,
        "test-key-v1",
        overrides={"asOf": future_dt.strftime("%Y-%m-%dT%H:%M:%SZ")},
    )
    if not expect_rejected("Future snapshot (> 300s) rejected correctly.", future_snap, trusted_keys):
        failures += 1

    replay_snap = create_and_sign_snapshot(private_key, "test-key-v1")
    seen_snapshots = set()
    normalize_snapshot(replay_snap, trusted_keys, seen_snapshots=seen_snapshots)
    try:
        normalize_snapshot(replay_snap, trusted_keys, seen_snapshots=seen_snapshots)
        print("[FAIL] Replay snapshot bypassed replay protection check!")
        failures += 1
    except EvidenceError:
        print("[PASS] Replay snapshot rejected correctly.")

    burn_snap_original = create_and_sign_snapshot(private_key, "test-key-v1")
    burn_snap_fake = json.loads(json.dumps(burn_snap_original))
    burn_snap_fake["integrity"]["signature"] = "a" * 44
    seen_snapshots_burn = set()

    try:
        normalize_snapshot(burn_snap_fake, trusted_keys, seen_snapshots=seen_snapshots_burn)
        print("[FAIL] Fake snapshot in burn attack bypassed signature check!")
        failures += 1
    except EvidenceError:
        pass

    if burn_snap_original["snapshotId"] in seen_snapshots_burn:
        print("[FAIL] Failed burn attack consumed snapshotId.")
        failures += 1

    try:
        normalize_snapshot(
            burn_snap_original, trusted_keys, seen_snapshots=seen_snapshots_burn
        )
        print("[PASS] Original snapshot accepted after failed burn attack.")
    except Exception as exc:
        print(f"[FAIL] Original snapshot rejected after failed burn attack: {exc}")
        failures += 1

    try:
        normalize_snapshot(
            burn_snap_original, trusted_keys, seen_snapshots=seen_snapshots_burn
        )
        print("[FAIL] Replay snapshot in burn attack bypassed replay check!")
        failures += 1
    except EvidenceError:
        print("[PASS] Replay snapshot rejected correctly in burn attack.")

    try:
        normalize_snapshot(
            create_and_sign_snapshot(private_key, "test-key-v1"),
            trusted_keys,
            seen_snapshots=None,
        )
        print("[FAIL] Missing replay registry failed open.")
        failures += 1
    except EvidenceError:
        print("[PASS] Missing replay registry rejected correctly.")

    try:
        normalize_snapshot(
            create_and_sign_snapshot(private_key, "test-key-v1"),
            trusted_keys=None,
            seen_snapshots=set(),
        )
        print("[FAIL] Missing trusted key registry failed open.")
        failures += 1
    except EvidenceError:
        print("[PASS] Missing trusted key registry rejected correctly.")

    print("--- AUDIT COMPLETE ---")
    if failures:
        raise SystemExit(f"{failures} v0.4 audit test(s) failed")


if __name__ == "__main__":
    run_tests()
