"""Read-only HTTP consumer for Pasarela reconciliation snapshots.

Standard-library only. It can GET a snapshot; it cannot mutate Pasarela.
Secrets are supplied by the caller/environment and are never logged.
"""
from __future__ import annotations
import json
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

from pasarela_adapter import EvidenceError
from reconciler import ReserveSnapshot, LiabilitySnapshot, reconcile


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


def normalize_snapshot(snapshot: dict) -> tuple[ReserveSnapshot, LiabilitySnapshot]:
    try:
        if snapshot["schemaVersion"] != "0.3":
            raise EvidenceError("unsupported schemaVersion")
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
        for name, value in (
            ("walletBalanceMinor", wallet_minor),
            ("eligibleSettledMinor", settled_minor),
            ("encumberedMinor", encumbered_minor),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise EvidenceError(f"{name} must be a non-negative integer")

        if encumbered_minor > settled_minor:
            raise EvidenceError("encumberedMinor cannot exceed eligibleSettledMinor")
        if not integrity.get("ledgerHash"):
            raise EvidenceError("ledgerHash is required")

        status = settlement["verificationStatus"]
        if status not in {"PENDING", "VERIFIED", "DISPUTED", "REJECTED"}:
            raise EvidenceError("invalid verificationStatus")

        reserve = ReserveSnapshot(
            eligible_liquid_mxn=(settled_minor - encumbered_minor) / 100,
            verified=status == "VERIFIED",
        )
        liability = LiabilitySnapshot(convertible_amr_fiat_mxn=wallet_minor / 100)
        return reserve, liability
    except (KeyError, TypeError) as exc:
        raise EvidenceError("malformed snapshot") from exc


def reconcile_snapshot(snapshot: dict) -> dict:
    reserve, liability = normalize_snapshot(snapshot)
    result = reconcile(reserve, liability)
    result["source_environment"] = snapshot["source"]["environment"]
    return result
