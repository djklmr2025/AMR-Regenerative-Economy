import base64
import copy
import os
import tempfile
import threading
import time
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from reconciliation.http_snapshot_consumer import EvidenceError, normalize_snapshot
from reconciliation.replay_store import ReplayStore, ReplayStoreError, SQLiteReplayStore


def keypair():
    private = ed25519.Ed25519PrivateKey.generate()
    pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private, pem


def signed_snapshot(private, key_id="test-key-v1", as_of_ts=None):
    ts = time.time() if as_of_ts is None else as_of_ts
    as_of = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    snap = {
        "schemaVersion": "0.4",
        "snapshotId": f"snap-{time.time_ns()}",
        "asOf": as_of,
        "source": {"system": "Pasarela-de-pago-AMR", "environment": "production"},
        "liabilities": {"walletBalanceMinor": 100000, "walletCount": 5, "currency": "MXN"},
        "settlementEvidence": {
            "eligibleSettledMinor": 100000, "encumberedMinor": 0,
            "currency": "MXN", "verificationStatus": "VERIFIED",
        },
        "integrity": {"ledgerHash": "hash123", "keyId": key_id},
    }
    lines = [
        "AMR-SNAPSHOT-SIG-V1", "schemaVersion=0.4",
        f"snapshotId={snap['snapshotId']}", f"asOf={snap['asOf']}",
        f"system={snap['source']['system']}",
        f"environment={snap['source']['environment']}",
        f"walletBalanceMinor={snap['liabilities']['walletBalanceMinor']}",
        f"walletCount={snap['liabilities']['walletCount']}",
        f"liabilityCurrency={snap['liabilities']['currency']}",
        f"eligibleSettledMinor={snap['settlementEvidence']['eligibleSettledMinor']}",
        f"encumberedMinor={snap['settlementEvidence']['encumberedMinor']}",
        f"settlementCurrency={snap['settlementEvidence']['currency']}",
        f"verificationStatus={snap['settlementEvidence']['verificationStatus']}",
        f"ledgerHash={snap['integrity']['ledgerHash']}", f"keyId={key_id}",
    ]
    snap["integrity"]["signature"] = base64.b64encode(
        private.sign("\n".join(lines).encode("utf-8"))
    ).decode("ascii")
    return snap


class BrokenStore(ReplayStore):
    def consume(self, snapshot_id, expires_at):
        raise ReplayStoreError("simulated database outage")


def run():
    failures = []
    def check(ok, label):
        print(("[PASS] " if ok else "[FAIL] ") + label)
        if not ok:
            failures.append(label)

    private, pem = keypair()
    keys = {"test-key-v1": pem}

    with tempfile.TemporaryDirectory() as td:
        db = os.path.join(td, "replay.db")

        # Valid + persistent replay across store reopen.
        snap = signed_snapshot(private)
        store = SQLiteReplayStore(db)
        try:
            normalize_snapshot(snap, keys, replay_store=store)
            accepted = True
        except Exception:
            accepted = False
        check(accepted, "valid authenticated snapshot accepted")

        reopened = SQLiteReplayStore(db)
        try:
            normalize_snapshot(snap, keys, replay_store=reopened)
            replay_rejected = False
        except EvidenceError:
            replay_rejected = True
        check(replay_rejected, "replay rejected after SQLite reopen/restart boundary")

        # Burn attack: invalid signature must not consume a fresh ID.
        original = signed_snapshot(private)
        forged = copy.deepcopy(original)
        forged["integrity"]["signature"] = base64.b64encode(b"x" * 64).decode("ascii")
        burn_db = os.path.join(td, "burn.db")
        burn_store = SQLiteReplayStore(burn_db)
        try:
            normalize_snapshot(forged, keys, replay_store=burn_store)
            forged_rejected = False
        except EvidenceError:
            forged_rejected = True
        check(forged_rejected, "forged burn-attempt signature rejected")
        try:
            normalize_snapshot(original, keys, replay_store=burn_store)
            original_after_burn = True
        except Exception:
            original_after_burn = False
        check(original_after_burn, "valid original accepted after failed burn attack")
        try:
            normalize_snapshot(original, keys, replay_store=burn_store)
            second_rejected = False
        except EvidenceError:
            second_rejected = True
        check(second_rejected, "second valid delivery rejected as replay")

        # Asymmetric freshness boundaries with explicit verifier time.
        now = time.time()
        stale = signed_snapshot(private, as_of_ts=now - 301)
        future_bad = signed_snapshot(private, as_of_ts=now + 31)
        future_ok = signed_snapshot(private, as_of_ts=now + 29)
        for label, candidate, should_accept in [
            ("stale >300s rejected", stale, False),
            ("future >30s rejected", future_bad, False),
            ("future within 30s accepted", future_ok, True),
        ]:
            try:
                normalize_snapshot(candidate, keys, current_time_s=now,
                                   replay_store=SQLiteReplayStore(os.path.join(td, candidate["snapshotId"] + ".db")))
                got = True
            except EvidenceError:
                got = False
            check(got == should_accept, label)

        # Fail closed on absent/broken replay protection.
        fresh = signed_snapshot(private)
        try:
            normalize_snapshot(fresh, keys, replay_store=None)
            missing_closed = False
        except EvidenceError:
            missing_closed = True
        check(missing_closed, "missing ReplayStore fails closed")
        try:
            normalize_snapshot(fresh, keys, replay_store=BrokenStore())
            broken_closed = False
        except EvidenceError:
            broken_closed = True
        check(broken_closed, "ReplayStore outage fails closed")

        # Missing trusted registry.
        try:
            normalize_snapshot(signed_snapshot(private), None, replay_store=SQLiteReplayStore(os.path.join(td, "nokeys.db")))
            keys_closed = False
        except EvidenceError:
            keys_closed = True
        check(keys_closed, "missing trusted-key registry fails closed")

        # Concurrent valid delivery: separate store objects/connections, same DB.
        race_db = os.path.join(td, "race.db")
        race_snap = signed_snapshot(private)
        barrier = threading.Barrier(2)
        outcomes = []
        lock = threading.Lock()

        def contender():
            local_store = SQLiteReplayStore(race_db)
            barrier.wait()
            try:
                normalize_snapshot(race_snap, keys, replay_store=local_store)
                outcome = "accepted"
            except EvidenceError as exc:
                outcome = "replay" if "replay detected" in str(exc) else "error"
            except Exception:
                outcome = "error"
            with lock:
                outcomes.append(outcome)

        threads = [threading.Thread(target=contender) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        check(sorted(outcomes) == ["accepted", "replay"],
              f"concurrent duplicate has exactly one winner: {outcomes}")

    print("--- v0.5-A AUDIT COMPLETE ---")
    if failures:
        raise SystemExit(f"{len(failures)} v0.5 audit test(s) failed: {failures}")
    print("[PASS] ALL v0.5-A DESTRUCTIVE TESTS PASSED")


if __name__ == "__main__":
    run()
