# OpenClaw Architecture for AMR Regenerative Economy

This document outlines the secure runtime environment designed for AMR/ARKAIOS persistent agents.

## 1. Principle of Separation of Powers

The architecture enforces a strict workflow to prevent unilateral control by any single agent.
The core stages are:
`PROPUESTA` -> `VERIFICACIÓN` -> `AUTORIZACIÓN` -> `EJECUCIÓN` -> `AUDITORÍA`

No individual agent is permitted to control all five stages.

### Action Classification Levels
- **LEVEL 0**: Reading and investigation.
- **LEVEL 1**: Creating files, simulations, and documentation.
- **LEVEL 2**: Creating branches, commits, and Pull Requests.
- **LEVEL 3**: Infrastructure changes (Requires Approval).
- **LEVEL 4**: Economic/Treasury changes (Requires Explicit Human Approval, followed by multiple authorizations).
- **LEVEL 5**: Irreversible or critical operations (Requires Explicit Human Approval, followed by multiple authorizations).

*Note: LEVEL 0-2 can be fully automated under policy.*

## 2. AMR Agent Roles

### AMR ORCHESTRATOR
- **Responsibility**: Coordinates workflows and tasks among other agents.
- **Restrictions**: 
  - CANNOT move funds.
  - CANNOT modify reserves unilaterally.
  - CANNOT reveal secrets.

### AMR RESEARCHER
- **Responsibility**: Investigation, data gathering, and documentation.
- **Permissions**: Read-only access by default.

### AMR ECONOMIST
- **Responsibility**: Economic simulations and modeling.
- **Permissions**: Can create and run scenarios in the simulator.
- **Restrictions**: NO control over real treasury.

### AMR AUDITOR
- **Responsibility**: Verifies Proof of Reserves, Proof of Assets, Proof of Production, and record integrity.
- **Restrictions**: Must be independent of the agent generating the operation/transaction.

### AMR ENVIRONMENTAL AGENT
- **Responsibility**: Models waste recovery, water, soil, materials, regenerative agriculture, and environmental impact.
- **Restrictions**: Must not assert food safety without concrete scientific data.

### AMR BUILDER
- **Responsibility**: Code and infrastructure implementation.
- **Permissions**: Can create code, branches, commits, and open Pull Requests.
- **Restrictions**:
  - CANNOT force push.
  - CANNOT delete `main` branch.
  - CANNOT modify secrets.
  - CANNOT move funds.
  - CANNOT alter productive contracts without approval.

## 3. OpenClaw Runtime Security

The runtime (`runtime/openclaw/`) is prepared to support OpenClaw execution, preferring containerized/sandboxed environments where possible.

### Initial Security Posture
OpenClaw will **NOT** receive the following initially:
- Master PAT (Personal Access Token)
- Wallet Private Keys
- Seed phrases
- Banking credentials
- Host root access
- Direct access to AMR Treasury

Agents will connect using least-privilege credentials. Destructive execution is disabled.
