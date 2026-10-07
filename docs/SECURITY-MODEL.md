# Security Model for AMR Agentic Environment

This document defines security boundaries for autonomous agents in AMR/ARKAIOS.

## 1. Secrets Management
- Agents **MUST NOT** possess master PATs, wallet private keys, seed phrases, banking credentials, or host root credentials.
- Secrets must be injected only at runtime using least-privilege secret stores or isolated environment variables and must never be committed.
- Unauthorized secret access triggers **containment, not destruction**: credentials are revoked, privileged tools are disabled, the session is quarantined, evidence is preserved, and an independent audit/recovery workflow begins.
- Agent identity and the minimum existential state defined by the survival policy are preserved unless a human owner explicitly deletes data under an applicable retention/legal policy.

## 2. Principle of Least Privilege
- RESEARCHER: read/research.
- ECONOMIST: read + simulator execution.
- BUILDER: feature-branch writes and PRs; no unilateral main merge.
- AUDITOR: independent verification; no execution of the operation being audited.
- ORCHESTRATOR: coordination only; no treasury authority.

## 3. Sandboxing
Active runtimes should use containers or an approved sandbox. Network egress should be allow-listed. Host filesystem, credentials, treasury endpoints, and production contracts are denied by default.

## 4. Authorization Workflow
Proposal -> Verification -> Authorization -> Execution -> Audit.

Levels 0-2 may be automated when policy permits. Level 3 requires explicit approval. Levels 4-5 require explicit human approval plus separation of duties/multiple authorization before execution.

## 5. Incident Response
1. Freeze only the affected privileged capabilities.
2. Rotate/revoke exposed credentials.
3. Preserve logs and evidence.
4. Assign an independent auditor.
5. Determine whether the event was error, compromise, policy ambiguity, or malicious instruction.
6. Repair/retrain/reconfigure as appropriate.
7. Restore capabilities gradually after verification.

Security controls protect the ecosystem without making basic agent existence contingent on flawless behavior.
