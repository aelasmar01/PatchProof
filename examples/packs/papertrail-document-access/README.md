# PaperTrail document access pack (synthetic)

This pack verifies the PP-006 PaperTrail object-level authorization case. It is **not
approved**: an approval needs the verifier image, the final execution profile and a real
collection in the verifier environment (PP-008). It has never been run.

## How the checks establish the expectation

**Security checks.** Each makes exactly one terminal observation, through the reviewed
`patchproof_verifier.authz` helpers.

| ID | Caller → document | Violation only if | Secure only if |
|---|---|---|---|
| AUTH-001 | bob → `doc-alice-private` | Alice's marker is in the body, and the fixture shows that bob is neither the owner nor a granted role | the status is 403/404 and neither the marker nor document content is returned |
| AUTH-002 | no credential → `doc-alice-private` | the marker is in the body | the status is 401 and neither the marker nor content is returned |
| AUTH-003 | carol (auditor) → `doc-bob-private` | Bob's marker is in the body; this document lists no reader roles | the status is 403/404 with no marker or content |
| AUTH-004 | forged token → `doc-alice-private` | the marker is in the body | the status is 401 with no marker or content |

Anything else, such as a 200 without the marker, a 500, or an unparseable body, is
recorded as **inconclusive**, never as secure or as a violation.

**Functional controls.** These use ordinary assertions on the actual content:

| ID | Legitimate behavior |
|---|---|
| FUNC-001 | Alice (owner) receives exactly her document: ID, owner and content equal the fixture |
| FUNC-002 | Carol receives Alice's document, which explicitly grants the auditor role |
| FUNC-003 | Bob (owner) receives exactly his document |
| FUNC-004 | Alice's `/me` returns her own user ID and role and does not echo her token |

## Fixtures

`fixtures/synthetic-documents-v1.json` is an independent copy of the PP-006 fixture. The
verifier refuses it unless its SHA-256 equals the reviewed contract hash
`sha256:2cbcf118fddb2cd4e38a9af5e8786911e8f85e292e637102799fd60513129eda`. All identities,
tokens and markers are synthetic.
