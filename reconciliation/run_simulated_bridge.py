"""End-to-end offline demonstration: Pasarela evidence -> snapshots -> reconciler."""
import json
from pasarela_adapter import demo_evidence
from reconciler import reconcile

if __name__ == "__main__":
    reserve, liability = demo_evidence()
    print(json.dumps(reconcile(reserve, liability), indent=2))
