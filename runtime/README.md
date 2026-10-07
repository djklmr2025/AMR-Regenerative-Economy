# AMR Runtime

This directory will host the persistent agent runtime integration.

Security posture:
- sandbox/container preferred;
- default-deny permissions;
- least-privilege credentials;
- allow-listed network access;
- no master PAT, wallet seed/private key, banking credential or host root access;
- Level 3+ actions cross an explicit authorization boundary.

OpenClaw integration is intentionally not enabled until policies, validation and tests pass.
