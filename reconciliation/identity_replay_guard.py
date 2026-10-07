"""Integrated AMR v0.5 security guard.

Strict order:
Identity -> Signature -> Authorization -> Freshness -> Replay consume -> Operation.
"""
from __future__ import annotations

import base64
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from identity.sovereign_identity import IdentityError
from reconciliation.replay_store import ReplayStore, ReplayStoreError

MAX_SNAPSHOT_AGE_S = 300
MAX_FUTURE_SKEW_S = 30


class IntegratedSecurityError(RuntimeError):
    pass


def _payload(snapshot: dict) -> bytes:
    liabilities = snapshot["liabilities"]
    settlement = snapshot["settlementEvidence"]
    integrity = snapshot["integrity"]
    lines = [
        "AMR-SNAPSHOT-SIG-V1", "schemaVersion=0.4",
        f"snapshotId={snapshot['snapshotId']}", f"asOf={snapshot['asOf']}",
        f"system={snapshot['source']['system']}",
        f"environment={snapshot['source']['environment']}",
        f"walletBalanceMinor={liabilities['walletBalanceMinor']}",
        f"walletCount={liabilities.get('walletCount', 0)}",
        f"liabilityCurrency={liabilities['currency']}",
        f"eligibleSettledMinor={settlement['eligibleSettledMinor']}",
        f"encumberedMinor={settlement['encumberedMinor']}",
        f"settlementCurrency={settlement['currency']}",
        f"verificationStatus={settlement['verificationStatus']}",
        f"ledgerHash={integrity['ledgerHash']}",
        f"keyId={integrity['keyId']}",
    ]
    return "\n".join(lines).encode("utf-8")


def authorize_snapshot(
    snapshot: dict,
    *,
    agent_id: str,
    capability: str,
    identity_registry,
    replay_store: ReplayStore,
    current_time_s: float,
) -> None:
    """Authorize once or fail closed; successful return means replay ID is consumed."""
    if identity_registry is None or replay_store is None:
        raise IntegratedSecurityError("identity registry and replay store are required")
    try:
        if snapshot.get("schemaVersion") != "0.4":
            raise IntegratedSecurityError("unsupported schemaVersion")
        key_id = snapshot["integrity"]["keyId"]
        signature_b64 = snapshot["integrity"]["signature"]

        # 1. Identity: resolve current trusted public material/lifecycle.
        try:
            record = identity_registry.resolve_key(agent_id, key_id, current_time_s)
        except IdentityError as exc:
            raise IntegratedSecurityError("identity rejected") from exc

        # 2. Signature: possession proof against registry-bound public key.
        try:
            public = serialization.load_pem_public_key(record.public_key_pem.encode("utf-8"))
            if not isinstance(public, Ed25519PublicKey):
                raise IntegratedSecurityError("registered key is not Ed25519")
            signature = base64.b64decode(signature_b64, validate=True)
            public.verify(signature, _payload(snapshot))
        except IntegratedSecurityError:
            raise
        except (InvalidSignature, ValueError) as exc:
            raise IntegratedSecurityError("invalid cryptographic signature") from exc
        except Exception as exc:
            raise IntegratedSecurityError("signature verification failed closed") from exc

        # 3. Authorization: a valid signature still grants only explicit capability.
        try:
            identity_registry.authorize(agent_id, key_id, capability, current_time_s)
        except IdentityError as exc:
            raise IntegratedSecurityError("capability rejected") from exc

        # 4. Freshness.
        try:
            as_of = datetime.strptime(
                snapshot["asOf"].replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S%z"
            ).timestamp()
        except (KeyError, ValueError, TypeError) as exc:
            raise IntegratedSecurityError("invalid asOf") from exc
        age = current_time_s - as_of
        if age > MAX_SNAPSHOT_AGE_S:
            raise IntegratedSecurityError("snapshot stale")
        if age < -MAX_FUTURE_SKEW_S:
            raise IntegratedSecurityError("snapshot too far in future")

        # 5. Replay consume occurs only after identity/signature/auth/freshness pass.
        try:
            consumed = replay_store.consume(snapshot["snapshotId"], as_of + MAX_SNAPSHOT_AGE_S)
        except ReplayStoreError as exc:
            raise IntegratedSecurityError("replay protection unavailable") from exc
        if not consumed:
            raise IntegratedSecurityError("replay detected")
    except (KeyError, TypeError) as exc:
        raise IntegratedSecurityError("malformed authenticated snapshot") from exc
