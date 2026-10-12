"""Verification packs: validation, exact collection and hashing (PROJECT_SPEC.md 7, PP-007).

Packs are reviewed test code that runs only in the verifier container. On the host they are
data: read as bytes, parsed with `ast`, hashed, and never imported.
"""
