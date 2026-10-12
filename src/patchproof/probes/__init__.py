"""PP-003 harmless container isolation probe suite.

`catalogue` fixes what is probed and which positive control guards each negative probe.
`interpret` turns raw observations into outcomes (pure). `evidence` builds the bounded
run record. `orchestrator` drives Docker through the typed runner, and only when the
A2/A3/A4 gates are satisfied.
"""
