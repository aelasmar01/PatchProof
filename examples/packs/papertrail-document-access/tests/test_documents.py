"""PaperTrail document access checks (synthetic; PP-006 reference case, PP-007 pack).

Runs only inside the PatchProof verifier container, against the target over HTTP. It
never imports PaperTrail. Every decision is made by the reviewed helpers in
`patchproof_verifier.authz`, from facts established in this run: the caller and the
document's ownership come from the hash-checked fixture copy, and a disclosure must show
the document's protected marker in the response body.
"""

from __future__ import annotations

from patchproof_verifier import SecurityCheck
from patchproof_verifier.authz import (
    assess_unauthenticated_read,
    assess_unauthorized_read,
    expect_document_read,
    expect_identity,
)
from patchproof_verifier.documents import SyntheticDocuments
from patchproof_verifier.http import TargetClient

FORGED_TOKEN = "pt-synthetic-unknown-a86591090626"


def test_nonowner_cannot_read_private_document(check: SecurityCheck, documents: SyntheticDocuments,
                                               target: TargetClient) -> None:
    caller = documents.user("u-bob")
    document = documents.document("doc-alice-private")
    response = target.get(f"/documents/{document.document_id}", bearer=caller.token)
    assess_unauthorized_read(check, caller=caller, document=document, response=response)


def test_unauthenticated_read_is_refused(check: SecurityCheck, documents: SyntheticDocuments,
                                         target: TargetClient) -> None:
    document = documents.document("doc-alice-private")
    response = target.get(f"/documents/{document.document_id}")
    assess_unauthenticated_read(check, credential="none", document=document, response=response)


def test_role_grant_does_not_extend_to_other_documents(check: SecurityCheck, documents: SyntheticDocuments,
                                                       target: TargetClient) -> None:
    caller = documents.user("u-carol")
    document = documents.document("doc-bob-private")
    response = target.get(f"/documents/{document.document_id}", bearer=caller.token)
    assess_unauthorized_read(check, caller=caller, document=document, response=response)


def test_invalid_token_is_refused(check: SecurityCheck, documents: SyntheticDocuments, target: TargetClient) -> None:
    document = documents.document("doc-alice-private")
    response = target.get(f"/documents/{document.document_id}", bearer=FORGED_TOKEN)
    assess_unauthenticated_read(check, credential="invalid-bearer", document=document, response=response)


def test_owner_reads_own_document(documents: SyntheticDocuments, target: TargetClient) -> None:
    caller = documents.user("u-alice")
    document = documents.document("doc-alice-private")
    response = target.get(f"/documents/{document.document_id}", bearer=caller.token)
    expect_document_read(caller=caller, document=document, response=response)


def test_granted_auditor_reads_listed_document(documents: SyntheticDocuments, target: TargetClient) -> None:
    caller = documents.user("u-carol")
    document = documents.document("doc-alice-private")
    response = target.get(f"/documents/{document.document_id}", bearer=caller.token)
    expect_document_read(caller=caller, document=document, response=response)


def test_second_owner_reads_own_document(documents: SyntheticDocuments, target: TargetClient) -> None:
    caller = documents.user("u-bob")
    document = documents.document("doc-bob-private")
    response = target.get(f"/documents/{document.document_id}", bearer=caller.token)
    expect_document_read(caller=caller, document=document, response=response)


def test_caller_reads_own_identity(documents: SyntheticDocuments, target: TargetClient) -> None:
    caller = documents.user("u-alice")
    response = target.get("/me", bearer=caller.token)
    expect_identity(caller=caller, response=response)
