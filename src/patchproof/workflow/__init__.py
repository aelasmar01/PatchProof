"""The v0.1 CLI workflow (PP-009): projects, plans, previews, exit codes and safe reports.

Every state-changing or executing step delegates to an accepted, security-controlled module:
the PP-005 Git wrapper, the PP-007/PP-008 pack approval, the PP-008 run authorization and
single-use execution, the runner's Docker policy and the PP-004 verdict engine. Nothing here
builds a Docker command, a mount, an environment or a verdict of its own.
"""
