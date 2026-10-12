# PaperTrail (synthetic verification fixture)

PaperTrail is a deliberately small document API used only as a PatchProof reference
fixture. It is not a product and must not be deployed.

- All users, bearer tokens and documents in `fixtures/synthetic/` are synthetic.
- Some revisions of this repository contain an intentional authorization defect.
- The application is started only inside PatchProof's isolated target container, never on
  a workstation.

Routes: `GET /health`, `GET /me`, `GET /documents/{document_id}`.
