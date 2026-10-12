"""Safe repository registration and read-only source snapshots (PROJECT_SPEC.md 9, PP-005).

ADR-004: execution consumes validated snapshots built from committed Git objects. The
original repository is read through a narrow, allowlisted Git wrapper with a sanitized
environment and fixed configuration overrides, and is never checked out or modified.
Repository contents, configuration, paths, and metadata are untrusted data.
"""
