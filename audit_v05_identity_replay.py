import base64
import copy
import os
import sqlite3
import tempfile
import time
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from identity.sovereign_identity import ACTIVE, PublicKeyRecord
from identity.sqlite_sovereign_identity import SQLiteSovereignIdentityRegistry
from reconciliation.identity_replay_guard import IntegratedSecurityError, authorize_snapshot
from reconciliation.replay_store import SQLiteReplayStore


def keypair():
    private = ed25519.Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return private, public


def snapshot(private, key_id, snapshot_id, ts):
    as_of = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    s = {
        "schemaVersion": "0.4", "snapshotId": snapshot_id, "asOf": as_of,
        "source": {"system": "Pasarela-de-pago-AMR", "environment": "production"},
        "liabilities": {"walletBalanceMinor": 1000, "walletCount": 1, "currency": "MXN"},
        "settlementEvidence": {"eligibleSettledMinor": 1000, "encumberedMinor": 0,
                               "currency": "MXN", "verificationStatus": "VERIFIED"},
        "integrity": {"ledgerHash": "audit-hash", "keyId": key_id},
    }
    L = [
        "AMR-SNAPSHOT-SIG-V1", "schemaVersion=0.4", f"snapshotId={snapshot_id}",
        f"asOf={as_of}", "system=Pasarela-de-pago-AMR", "environment=production",
        "walletBalanceMinor=1000", "walletCount=1", "liabilityCurrency=MXN",
        "eligibleSettledMinor=1000", "encumberedMinor=0", "settlementCurrency=MXN",
        "verificationStatus=VERIFIED", "ledgerHash=audit-hash", f"keyId={key_id}",
    ]
    s["integrity"]["signature"] = base64.b64encode(
        private.sign("\n".join(L).encode())
    ).decode()
    return s


def replay_contains(db, snapshot_id):
    conn = sqlite3.connect(db)
    try:
        return conn.execute(
            "SELECT 1 FROM seen_snapshots WHERE snapshot_id=?", (snapshot_id,)
        ).fetchone() is not None
    finally:
        conn.close()


def run():
    failures = []
    def check(ok, label):
        print(("[PASS] " if ok else "[FAIL] ") + label)
        if not ok: failures.append(label)

    now = time.time()
    with tempfile.TemporaryDirectory() as td:
        id_db = os.path.join(td, "identity.db")
        rp_db = os.path.join(td, "replay.db")
        ids = SQLiteSovereignIdentityRegistry(id_db)
        replay = SQLiteReplayStore(rp_db)
        old_priv, old_pub = keypair()
        new_priv, new_pub = keypair()
        ids.register_agent("agent:pasarela",
                           PublicKeyRecord("k1", "Ed25519", old_pub, ACTIVE, now-1),
                           {"reconciliation:submit"}, now)
        ids.rotate_key("agent:pasarela", "k1",
                       PublicKeyRecord("k2", "Ed25519", new_pub, ACTIVE, now),
                       now, administrative_authorized=True)

        # 1-2 rotated key: reject, do not burn.
        sid = "same-id-after-rotated-attack"
        bad = snapshot(old_priv, "k1", sid, now)
        try:
            authorize_snapshot(bad, agent_id="agent:pasarela",
                               capability="reconciliation:submit",
                               identity_registry=ids, replay_store=replay, current_time_s=now)
            rejected = False
        except IntegratedSecurityError:
            rejected = True
        check(rejected, "rotated-key attack rejected")
        check(not replay_contains(rp_db, sid), "rotated-key attack does not burn replay ID")

        # Legitimate request using same snapshotId but current key is accepted.
        good = snapshot(new_priv, "k2", sid, now)
        try:
            authorize_snapshot(good, agent_id="agent:pasarela",
                               capability="reconciliation:submit",
                               identity_registry=ids, replay_store=replay, current_time_s=now)
            accepted = True
        except IntegratedSecurityError:
            accepted = False
        check(accepted, "legitimate current key accepted with previously attacked snapshotId")
        check(replay_contains(rp_db, sid), "legitimate request consumes replay ID")
        try:
            authorize_snapshot(good, agent_id="agent:pasarela",
                               capability="reconciliation:submit",
                               identity_registry=ids, replay_store=replay, current_time_s=now)
            replay_rejected = False
        except IntegratedSecurityError:
            replay_rejected = True
        check(replay_rejected, "second legitimate delivery rejected as replay")

        # 6-7 forged signature: reject before replay consume.
        sid2 = "same-id-after-forgery"
        forged = snapshot(new_priv, "k2", sid2, now)
        forged["integrity"]["signature"] = base64.b64encode(b"x"*64).decode()
        try:
            authorize_snapshot(forged, agent_id="agent:pasarela",
                               capability="reconciliation:submit",
                               identity_registry=ids, replay_store=replay, current_time_s=now)
            forged_rejected = False
        except IntegratedSecurityError:
            forged_rejected = True
        check(forged_rejected, "forged signature rejected before replay")
        check(not replay_contains(rp_db, sid2), "forged signature does not burn replay ID")

        # 8-9 unauthorized capability: valid identity/signature but no replay burn.
        sid3 = "same-id-after-permission-attack"
        no_perm = snapshot(new_priv, "k2", sid3, now)
        try:
            authorize_snapshot(no_perm, agent_id="agent:pasarela",
                               capability="identity:admin",
                               identity_registry=ids, replay_store=replay, current_time_s=now)
            perm_rejected = False
        except IntegratedSecurityError:
            perm_rejected = True
        check(perm_rejected, "unauthorized capability rejected")
        check(not replay_contains(rp_db, sid3), "unauthorized capability does not burn replay ID")

        # 10-11 stale request: reject before replay consume.
        sid4 = "same-id-after-stale"
        stale = snapshot(new_priv, "k2", sid4, now-301)
        try:
            authorize_snapshot(stale, agent_id="agent:pasarela",
                               capability="reconciliation:submit",
                               identity_registry=ids, replay_store=replay, current_time_s=now)
            stale_rejected = False
        except IntegratedSecurityError:
            stale_rejected = True
        check(stale_rejected, "stale authenticated request rejected")
        check(not replay_contains(rp_db, sid4), "stale request does not burn replay ID")

        # 12 revoked current key: mathematically valid signature but no burn.
        ids.revoke_key("agent:pasarela", "k2", now+1, administrative_authorized=True)
        sid5 = "same-id-after-revoked"
        revoked = snapshot(new_priv, "k2", sid5, now+2)
        try:
            authorize_snapshot(revoked, agent_id="agent:pasarela",
                               capability="reconciliation:submit",
                               identity_registry=ids, replay_store=replay, current_time_s=now+2)
            revoked_rejected = False
        except IntegratedSecurityError:
            revoked_rejected = True
        check(revoked_rejected, "revoked mathematically-valid key rejected")
        check(not replay_contains(rp_db, sid5), "revoked-key attack does not burn replay ID")

    print("--- v0.5 IDENTITY + REPLAY INTEGRATION AUDIT COMPLETE ---")
    if failures:
        raise SystemExit(f"{len(failures)} integrated security test(s) failed: {failures}")
    print("[PASS] ALL 13 IDENTITY + REPLAY INTEGRATION TESTS PASSED")


if __name__ == "__main__":
    run()
