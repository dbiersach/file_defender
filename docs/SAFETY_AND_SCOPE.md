# Safety and scope

This project is defensive. It should not generate, encrypt, corrupt, or mass-modify files.

Allowed work:

- Monitor file access metadata.
- Compute benign behavior baselines.
- Detect anomalous event rates, entropy changes, directory breadth, and extension patterns.
- Alert the logged-on user.
- Optionally pause a suspicious process only in a controlled lab after explicit opt-in.

Out of scope:

- Writing ransomware, encryption loops, destructive tests, persistence, privilege escalation, stealth, or evasion.
- Running experiments on real personal files without backups.
- Automatically killing processes by default.

Recommended lab setup:

- Use a VM or disposable Linux account.
- Use synthetic benign datasets and copied test files.
- Keep backups and snapshots.
- Start with alert-only mode.
