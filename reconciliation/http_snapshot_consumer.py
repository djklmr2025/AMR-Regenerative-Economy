"""Read-only HTTP consumer for authenticated Pasarela reconciliation snapshots."""
from __future__ import annotations

import base64
import json
import time
from datetime import datetime
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from pasarela_adapter import EvidenceError
from reconciler import ReserveSnapshot, LiabilitySnapshot, reconcile
from replay_store import ReplayStore, ReplayStoreError


MAX_SNAPSHOT_AGE_S = 300
MAX_FUTURE_SKEW_S = 30


class SnapshotTransportError(RuntimeError):
    pass


def fetch_snapshot(base_url: str, api_key: str, timeout_seconds: float = 5.0) -> dict:
    if not api_key:
        raise SnapshotTransportError("reconciliation API key is required")
    parsed = urlparse(base_url)
    if parsed.scheme != "https":
        raise SnapshotTransportError("HTTPS is required")
    url = base_url.rstrip("/") + "/api/fiat/internal/reconciliation/v1/snapshot"
    req = Request(url, headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"}, method="GET")
    try:
        with urlopen(req, timeout=timeout_seconds) as response:
            if response.status != 200:
                raise SnapshotTransportError(f"unexpected HTTP status {response.status}")
            return json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise SnapshotTransportError("snapshot fetch failed closed") from exc


def normalize_snapshot(
    snapshot: dict,
    trusted_keys: dict[str, str] | None = None,
    current_time_s: float | None = None,
    replay_store: ReplayStore | None = None,
) -> tuple[ReserveSnapshot, LiabilitySnapshot]:
    try:
        if snapshot.get("schemaVersion") != "0.4":
            raise EvidenceError("unsupported schemaVersion, requires 0.4")
        if snapshot["source"]["system"] != "Pasarela-de-pago-AMR":
            raise EvidenceError("unexpected source system")

        liabilities = snapshot["liabilities"]
        settlement = snapshot["settlementEvidence"]
        integrity = snapshot["integrity"]
        if liabilities["currency"] != "MXN" or settlement["currency"] != "MXN":
            raise EvidenceError("snapshot currency must be MXN")

        wallet_minor = liabilities["walletBalanceMinor"]
        settled_minor = settlement["eligibleSettledMinor"]
        encumbered_minor = settlement["encumberedMinor"]
        for name, value in (("walletBalanceMinor", wallet_minor), ("eligibleSettledMinor", settled_minor), ("encumberedMinor", encumbered_minor)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise EvidenceError(f"{name} must be a non-negative integer")
        if encumbered_minor > settled_minor:
            raise EvidenceError("encumberedMinor cannot exceed eligibleSettledMinor")

        ledger_hash = integrity.get("ledgerHash")
        if not ledger_hash:
            raise EvidenceError("ledgerHash is required")
        status = settlement["verificationStatus"]
        if status not in {"PENDING", "VERIFIED", "DISPUTED", "REJECTED"}:
            raise EvidenceError("invalid verificationStatus")

        snapshot_id = snapshot.get("snapshotId")
        as_of_str = snapshot.get("asOf")
        key_id = integrity.get("keyId")
        signature_b64 = integrity.get("signature")
        if not all([snapshot_id, as_of_str, key_id, signature_b64]):
            raise EvidenceError("missing v0.4 integrity fields (snapshotId, asOf, keyId, signature)")

        try:
            as_of_dt = datetime.strptime(as_of_str.replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S%z")
            as_of_ts = as_of_dt.timestamp()
        except ValueError as exc:
            raise EvidenceError("invalid asOf format") from exc

        now_ts = current_time_s if current_time_s is not None else time.time()
        age_s = now_ts - as_of_ts
        if age_s > MAX_SNAPSHOT_AGE_S:
            raise EvidenceError("snapshot is stale (>300s old)")
        if age_s < -MAX_FUTURE_SKEW_S:
            raise EvidenceError("snapshot is too far in the future (>30s)")

        if replay_store is None:
            raise EvidenceError("persistent replay store is required")
        if not trusted_keys:
            raise EvidenceError("trusted Ed25519 key registry is required")
        if key_id not in trusted_keys:
            raise EvidenceError(f"unauthorized keyId: {key_id}")

        try:
            pub_key = serialization.load_pem_public_key(trusted_keys[key_id].encode("utf-8"))
        except Exception as exc:
            raise EvidenceError("invalid public key configured for keyId") from exc
        if not isinstance(pub_key, Ed25519PublicKey):
            raise EvidenceError("public key is not Ed25519")

        payload_lines = [
            "AMR-SNAPSHOT-SIG-V1", "schemaVersion=0.4",
            f"snapshotId={snapshot_id}", f"asOf={as_of_str}",
            f"system={snapshot['source']['system']}",
            f"environment={snapshot['source']['environment']}",
            f"walletBalanceMinor={wallet_minor}",
            f"walletCount={liabilities.get('walletCount', 0)}",
            f"liabilityCurrency={liabilities['currency']}",
            f"eligibleSettledMinor={settled_minor}",
            f"encumberedMinor={encumbered_minor}",
            f"settlementCurrency={settlement['currency']}",
            f"verificationStatus={status}", f"ledgerHash={ledger_hash}",
            f"keyId={key_id}",
        ]
        payload_bytes = "\n".join(payload_lines).encode("utf-8")
        try:
            signature = base64.b64decode(signature_b64, validate=True)
            pub_key.verify(signature, payload_bytes)
        except (InvalidSignature, ValueError) as exc:
            raise EvidenceError("invalid cryptographic signature") from exc
        except Exception as exc:
            raise EvidenceError("signature verification process failed") from exc

        # Authenticate first. Only a valid signature may attempt to consume the ID.
        # Keep replay state at least until the signed snapshot can no longer be fresh.
        expires_at = as_of_ts + MAX_SNAPSHOT_AGE_S
        try:
            consumed = replay_store.consume(snapshot_id, expires_at)
        except ReplayStoreError as exc:
            raise EvidenceError("replay protection unavailable; failing closed") from exc
        except Exception as exc:
            raise EvidenceError("unexpected replay protection failure; failing closed") from exc
        if not consumed:
            raise EvidenceError(f"replay detected: snapshotId {snapshot_id} already processed")

        reserve = ReserveSnapshot(eligible_liquid_mxn=(settled_minor - encumbered_minor) / 100, verified=status == "VERIFIED")
        liability = LiabilitySnapshot(convertible_amr_fiat_mxn=wallet_minor / 100)
        return reserve, liability
    except (KeyError, TypeError) as exc:
        raise EvidenceError("malformed snapshot") from exc


def reconcile_snapshot(
    snapshot: dict,
    trusted_keys: dict[str, str] | None = None,
    current_time_s: float | None = None,
    replay_store: ReplayStore | None = None,
) -> dict:
    reserve, liability = normalize_snapshot(snapshot, trusted_keys, current_time_s, replay_store)
    result = reconcile(reserve, liability)
    result["source_environment"] = snapshot["source"]["environment"]
    return result
