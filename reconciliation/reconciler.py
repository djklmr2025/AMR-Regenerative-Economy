"""Pure AMR v0.3 fiat reconciliation logic. No network or payment access."""
from dataclasses import dataclass, asdict
import json


@dataclass(frozen=True)
class ReserveSnapshot:
    eligible_liquid_mxn: float
    verified: bool


@dataclass(frozen=True)
class LiabilitySnapshot:
    convertible_amr_fiat_mxn: float
    restricted_settlement_mxn: float = 0.0
    prudential_buffer_mxn: float = 0.0


def reconcile(reserves: ReserveSnapshot, liabilities: LiabilitySnapshot):
    values = [
        reserves.eligible_liquid_mxn,
        liabilities.convertible_amr_fiat_mxn,
        liabilities.restricted_settlement_mxn,
        liabilities.prudential_buffer_mxn,
    ]
    if any(v < 0 for v in values):
        raise ValueError("Reconciliation inputs cannot be negative")

    required = (
        liabilities.convertible_amr_fiat_mxn
        + liabilities.restricted_settlement_mxn
        + liabilities.prudential_buffer_mxn
    )
    eligible = reserves.eligible_liquid_mxn if reserves.verified else 0.0
    headroom = eligible - required
    ratio = None if required == 0 else eligible / required

    if not reserves.verified:
        state = "BACKING_PENDING"
    elif headroom < 0:
        state = "DEFICIT"
    else:
        state = "FULLY_BACKED"

    return {
        "state": state,
        "eligible_liquid_mxn": round(eligible, 2),
        "required_liquid_mxn": round(required, 2),
        "headroom_mxn": round(headroom, 2),
        "coverage_ratio": None if ratio is None else round(ratio, 6),
        "new_conversion_allowed": state == "FULLY_BACKED",
        "max_additional_convertible_mxn": round(max(0.0, headroom), 2)
            if state == "FULLY_BACKED" else 0.0,
    }


if __name__ == "__main__":
    result = reconcile(
        ReserveSnapshot(eligible_liquid_mxn=15000, verified=True),
        LiabilitySnapshot(
            convertible_amr_fiat_mxn=10000,
            restricted_settlement_mxn=1000,
            prudential_buffer_mxn=1000,
        ),
    )
    print(json.dumps(result, indent=2))
