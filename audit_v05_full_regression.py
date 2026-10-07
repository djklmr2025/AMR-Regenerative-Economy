"""AMR v0.5 full security regression orchestrator.

Runs each destructive auditor in an isolated Python process and fails closed
if any auditor exits nonzero.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time


AUDITS = [
    ("v0.5-A Persistent Anti-Replay", "audit_v05.py"),
    ("v0.5-B Sovereign Identity", "audit_v05_identity.py"),
    ("v0.5-C Persistent Sovereign Identity", "audit_v05_persistent_identity.py"),
    ("v0.5 Integrated Identity + Replay", "audit_v05_identity_replay.py"),
]


def run():
    repo_root = os.path.dirname(os.path.abspath(__file__))
    env = os.environ.copy()
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = repo_root + (os.pathsep + existing if existing else "")

    failures = []
    started = time.time()

    print("=== AMR v0.5 FULL SECURITY REGRESSION ===")
    print(f"Python: {sys.executable}")
    print(f"Repository: {repo_root}")

    for label, script in AUDITS:
        path = os.path.join(repo_root, script)
        print(f"\n>>> START {label} :: {script}")
        if not os.path.isfile(path):
            print(f"[FAIL] missing auditor: {script}")
            failures.append((label, "missing auditor"))
            continue

        completed = subprocess.run(
            [sys.executable, path],
            cwd=repo_root,
            env=env,
            text=True,
        )
        if completed.returncode == 0:
            print(f"<<< [PASS] {label} :: exit 0")
        else:
            print(f"<<< [FAIL] {label} :: exit {completed.returncode}")
            failures.append((label, f"exit {completed.returncode}"))

    elapsed = time.time() - started
    print("\n=== AMR v0.5 FULL REGRESSION SUMMARY ===")
    print(f"Auditors executed: {len(AUDITS)}")
    print(f"Elapsed seconds: {elapsed:.2f}")

    if failures:
        for label, reason in failures:
            print(f"[FAIL] {label}: {reason}")
        raise SystemExit(f"{len(failures)} regression auditor(s) failed")

    for label, _ in AUDITS:
        print(f"[PASS] {label}")
    print("[PASS] ALL AMR v0.5 SECURITY REGRESSION AUDITORS PASSED")


if __name__ == "__main__":
    run()
