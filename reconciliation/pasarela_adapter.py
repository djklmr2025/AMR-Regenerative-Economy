"""Pasarela -> normalized AMR v0.3 snapshots.

Pure adapter: no network, Stripe, MongoDB, wallet, or payment execution.
It accepts already-exported evidence dictionaries and fails closed.
"""
from datetime import datetime, timezone
from typing import Any, Dict

from reconciler import ReserveSnapshot, LiabilitySnapshot


class EvidenceError(ValueError):
    pass


def _non_negative_number(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvidenceError(f"{field} must be numeric")
    value = float(value)
    if value < 0:
        raise EvidenceError(f"{field} cannot be negative")
    return value


def reserve_from_pasarela_evidence(evidence: Dict[str, Any]) -> ReserveSnapshot:
    """Normalize a simulated/exported Pasarela reserve attestation."""
    required = {"currency", "settled_mxn", "audit_status", "evidence_uri", "as_of"}
    missing = required - evidence.keys()
    if missing:
        raise EvidenceError(f"missing reserve fields: {sorted(missing)}")
    if evidence["currency"] != "MXN":
        raise EvidenceError("only MXN reserve evidence is eligible")
    if evidence["audit_status"] not in {"PENDING", "VERIFIED", "DISPUTED", "REJECTED"}:
        raise EvidenceError("invalid audit_status")
    if not isinstance(evidence["evidence_uri"], str) or not evidence["evidence_uri"]:
        raise EvidenceError("evidence_uri is required")

    settled = _non_negative_number(evidence["settled_mxn"], "settled_mxn")
    encumbered = _non_negative_number(evidence.get("encumbered_mxn", 0), "encumbered_mxn")
    if encumbered > settled:
        raise EvidenceError("encumbered_mxn cannot exceed settled_mxn")

    # Pending Stripe sessions, successful redirects, internal AMR balances and
    # regenerative production are deliberately absent from this calculation.
    eligible = settled - encumbered
    verified = evidence["audit_status"] == "VERIFIED"
    return ReserveSnapshot(eligible_liquid_mxn=eligible, verified=verified)


def liability_from_amr_ledger(evidence: Dict[str, Any]) -> LiabilitySnapshot:
    """Normalize a simulated/exported AMR-FIAT liability ledger snapshot."""
    required = {"convertible_amr_fiat_mxn", "as_of", "ledger_hash"}
    missing = required - evidence.keys()
    if missing:
        raise EvidenceError(f"missing liability fields: {sorted(missing)}")
    if not isinstance(evidence["ledger_hash"], str) or not evidence["ledger_hash"]:
        raise EvidenceError("ledger_hash is required")

    return LiabilitySnapshot(
        convertible_amr_fiat_mxn=_non_negative_number(
            evidence["convertible_amr_fiat_mxn"], "convertible_amr_fiat_mxn"
        ),
        restricted_settlement_mxn=_non_negative_number(
            evidence.get("restricted_settlement_mxn", 0), "restricted_settlement_mxn"
        ),
        prudential_buffer_mxn=_non_negative_number(
            evidence.get("prudential_buffer_mxn", 0), "prudential_buffer_mxn"
        ),
    )


def demo_evidence():
    now = datetime.now(timezone.utc).isoformat()
    reserve = reserve_from_pasarela_evidence({
        "currency": "MXN",
        "settled_mxn": 15000,
        "encumbered_mxn": 1000,
        "audit_status": "VERIFIED",
        "evidence_uri": "https://example.invalid/simulated-attestation",
        "as_of": now,
        # Ignored by design if supplied:
        "pending_checkout_mxn": 999999,
        "regenerative_production_value": 999999,
    })
    liability = liability_from_amr_ledger({
        "convertible_amr_fiat_mxn": 10000,
        "restricted_settlement_mxn": 1000,
        "prudential_buffer_mxn": 1000,
        "ledger_hash": "SIMULATED",
        "as_of": now,
    })
    return reserve, liability
