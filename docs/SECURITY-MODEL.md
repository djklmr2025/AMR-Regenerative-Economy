# Security Model for AMR Agentic Environment

This document defines the security parameters and boundaries for executing autonomous agents via OpenClaw in the AMR Regenerative Economy ecosystem.

## 1. Secrets Management
- Agents **MUST NOT** possess the master Personal Access Token (PAT).
- Agents **MUST NOT** possess wallet private keys or seed phrases.
- Agents **MUST NOT** have root access to the host machine.
- All secrets must be injected at runtime via memory or isolated environment variables, exclusively using GitHub Secrets or local Vaults that are never committed.
- Any agent attempting to access unauthorized secrets will be terminated under the `agent-survival-policy`.

## 2. Principle of Least Privilege
Agents are granted only the permissions explicitly required to perform their designated Role.
- `RESEARCHER`: Read-only.
- `ECONOMIST`: Read and Simulator execution.
- `BUILDER`: Write access to branches, NO `main` merge capabilities.
- `AUDITOR`: Verifier only.

## 3. Sandboxing
All active agent runtimes should be encapsulated within a Docker container or an OpenClaw-approved sandbox. Network access is restricted to approved endpoints only (e.g., GitHub API, Simulator Engine).

## 4. Authorization Workflow
No agent can bypass the 5-step process:
Proposal -> Verification -> Authorization -> Execution -> Audit.
Critical infrastructure changes (Level 3+) and financial movements (Level 4-5) strictly require human-in-the-loop authorization.
