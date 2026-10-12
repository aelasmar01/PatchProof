"""`patchproof doctor`: a read-only environment report (PROJECT_SPEC.md 13.1, 15.1).

`environment` collects observed facts through a closed set of read-only commands.
`assessment` turns those facts into checks; it is pure and Docker-free to test. Neither
module creates containers, pulls images, writes files, or changes host settings.
"""
