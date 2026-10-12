"""Fixed container execution policy, typed Docker CLI wrapper, and ownership-scoped cleanup.

ADR-009: security-sensitive container settings are constants in this package. No
caller, profile, or request can supply a Docker option.
"""
