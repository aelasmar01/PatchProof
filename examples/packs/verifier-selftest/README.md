# Verifier self-test pack (SYNTHETIC)

Used only by PP-008 gate C step C1 to check pytest 9.0.3, the PatchProof launcher, the plugin
and the event channel inside the approved verifier image. It makes no network requests, tests no
application, and produces no security findings. It deliberately violates the static pack policy
to exercise harness errors, and it can never be approved (`core.approvals` refuses its pack ID).
