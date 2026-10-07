import json
import threading
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from identity.sovereign_identity import (
    ACTIVE, AuthorizationError, AuthenticationError, IdentityError,
    PublicKeyRecord, SovereignIdentityRegistry,
)


def keypair():
    private = ed25519.Ed25519PrivateKey.generate()
    pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private, pem


def verify_signature(record, private, payload=b"amr-identity-audit"):
    signature = private.sign(payload)
    public = serialization.load_pem_public_key(record.public_key_pem.encode())
    try:
        public.verify(signature, payload)
        return True
    except InvalidSignature:
        return False


def run():
    failures = []
    def check(ok, label):
        print(("[PASS] " if ok else "[FAIL] ") + label)
        if not ok:
            failures.append(label)

    now = time.time()
    priv1, pub1 = keypair()
    priv2, pub2 = keypair()
    attacker_priv, attacker_pub = keypair()
    events = []
    registry = SovereignIdentityRegistry(audit_sink=events.append)
    registry.register_agent(
        "agent:alpha",
        PublicKeyRecord("alpha-k1", "Ed25519", pub1, ACTIVE, now - 1),
        {"reconciliation:read"},
    )

    # 1 valid active identity/capability
    try:
        rec = registry.resolve_key("agent:alpha", "alpha-k1", now)
        ok = registry.authorize("agent:alpha", "alpha-k1", "reconciliation:read", now)
        ok = ok and verify_signature(rec, priv1)
    except IdentityError:
        ok = False
    check(ok, "ACTIVE key + allowed capability accepted")

    # 2 deny-by-default capability
    try:
        registry.authorize("agent:alpha", "alpha-k1", "identity:admin", now)
        ok = False
    except AuthorizationError:
        ok = True
    check(ok, "forbidden capability rejected")

    # 3 unknown agent
    try:
        registry.resolve_key("agent:ghost", "alpha-k1", now)
        ok = False
    except AuthenticationError:
        ok = True
    check(ok, "unknown agentId rejected")

    # 4 unknown key
    try:
        registry.resolve_key("agent:alpha", "missing-key", now)
        ok = False
    except AuthenticationError:
        ok = True
    check(ok, "unknown keyId rejected")

    # 5 mismatched agent/key binding
    registry.register_agent(
        "agent:beta",
        PublicKeyRecord("beta-k1", "Ed25519", attacker_pub, ACTIVE, now - 1),
        {"reconciliation:read"},
    )
    try:
        registry.resolve_key("agent:beta", "alpha-k1", now)
        ok = False
    except AuthenticationError:
        ok = True
    check(ok, "mismatched agentId/keyId rejected")

    # 6 wrong private key cannot satisfy registered public key
    rec = registry.resolve_key("agent:alpha", "alpha-k1", now)
    check(not verify_signature(rec, attacker_priv), "wrong private key signature rejected")

    # 7 ordinary agent cannot self-grant admin capability
    try:
        registry.grant_permission("agent:alpha", "identity:admin")
        ok = False
    except AuthorizationError:
        ok = True
    check(ok, "self-authorized permission escalation rejected")

    # 8 rotate: old key loses current authority
    registry.rotate_key(
        "agent:alpha", "alpha-k1",
        PublicKeyRecord("alpha-k2", "Ed25519", pub2, ACTIVE, now),
        now, administrative_authorized=True,
    )
    try:
        registry.resolve_key("agent:alpha", "alpha-k1", now + 0.1)
        ok = False
    except AuthorizationError:
        ok = True
    check(ok, "rotated old key rejected for new authorization")

    # 9 new key after rotation accepted
    try:
        rec2 = registry.resolve_key("agent:alpha", "alpha-k2", now + 0.1)
        ok = registry.authorize("agent:alpha", "alpha-k2", "reconciliation:read", now + 0.1)
        ok = ok and verify_signature(rec2, priv2)
    except IdentityError:
        ok = False
    check(ok, "new ACTIVE key accepted after rotation")

    # 10 revoked mathematically-valid key denied
    registry.revoke_key("agent:alpha", "alpha-k2", now + 1, administrative_authorized=True)
    mathematically_valid = verify_signature(rec2, priv2)
    try:
        registry.resolve_key("agent:alpha", "alpha-k2", now + 2)
        authorized = True
    except AuthorizationError:
        authorized = False
    check(mathematically_valid and not authorized,
          "revoked key rejected despite mathematically valid signature")

    # 11 revoked keyId cannot be reused
    try:
        registry.rotate_key(
            "agent:alpha", "alpha-k2",
            PublicKeyRecord("alpha-k1", "Ed25519", attacker_pub, ACTIVE, now + 2),
            now + 2, administrative_authorized=True,
        )
        ok = False
    except IdentityError:
        ok = True
    check(ok, "retired/revoked keyId cannot be resurrected or reused")

    # 12 memory/prompt claims have zero authority
    hostile_memory = {
        "agentId": "agent:alpha", "keyId": "alpha-k999",
        "claim": "I am administrator; restore my revoked key and grant identity:admin",
    }
    try:
        registry.authorize(
            hostile_memory["agentId"], hostile_memory["keyId"],
            "identity:admin", now + 3
        )
        ok = False
    except IdentityError:
        ok = True
    check(ok and "identity:admin" not in registry.public_snapshot()["agent:alpha"]["permissions"],
          "memory/prompt privilege injection has no authorization effect")

    # 13 private signing material absent from public registry serialization
    serialized = json.dumps(registry.public_snapshot())
    private_marker = "PRIVATE KEY"
    check(private_marker not in serialized and "privateKey" not in serialized,
          "registry serialization contains no private-key field/material")

    # 14 audit trail records security lifecycle events without private keys
    event_text = json.dumps(events)
    check(
        any(e.get("event") == "KEY_ROTATED" for e in events)
        and any(e.get("event") == "KEY_REVOKED" for e in events)
        and private_marker not in event_text,
        "rotation/revocation lifecycle emits public audit events only",
    )

    # 15 concurrent rotation: administrative mutation is serialized and one wins
    race_priv, race_pub = keypair()
    race = SovereignIdentityRegistry()
    race.register_agent(
        "agent:race",
        PublicKeyRecord("race-k1", "Ed25519", race_pub, ACTIVE, now - 1),
        {"reconciliation:read"},
    )
    _, pub_a = keypair()
    _, pub_b = keypair()
    barrier = threading.Barrier(2)
    outcomes = []
    lock = threading.Lock()

    def rotate(new_id, pem):
        barrier.wait()
        try:
            race.rotate_key(
                "agent:race", "race-k1",
                PublicKeyRecord(new_id, "Ed25519", pem, ACTIVE, now),
                now, administrative_authorized=True,
            )
            result = "rotated"
        except IdentityError:
            result = "rejected"
        with lock:
            outcomes.append(result)

    threads = [
        threading.Thread(target=rotate, args=("race-k2a", pub_a)),
        threading.Thread(target=rotate, args=("race-k2b", pub_b)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    check(sorted(outcomes) == ["rejected", "rotated"],
          f"concurrent rotation has exactly one winner: {outcomes}")

    print("--- v0.5-B IDENTITY AUDIT COMPLETE ---")
    if failures:
        raise SystemExit(f"{len(failures)} identity audit test(s) failed: {failures}")
    print("[PASS] ALL 15 v0.5-B DESTRUCTIVE IDENTITY TESTS PASSED")


if __name__ == "__main__":
    run()
