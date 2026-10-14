"""Project registration records (schemas/project-registration.schema.json 1.0; PP-009).

A project is one explicitly selected, canonical local Git repository that the owner registered
with `patchproof project add` (PROJECT_SPEC.md 6, 9.1, 13.1). The record holds where the
repository is and what the owner said when registering it; it holds no repository content.
Registration does not approve a pack, a plan or a run.

Semantic checks that need computation (the ID derived from the canonical path and the typed
confirmation) are in `workflow.projects`.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AfterValidator, Field, StringConstraints

from .common import Identifier, LongText, Record, SchemaVersion, ShortText, Timestamp, matches, unique_list
from .pack import Reviewer

ProjectId = Annotated[str, matches(r"^prj-[0-9a-f]{16}$")]
CanonicalPath = Annotated[str, StringConstraints(min_length=2, max_length=1024), matches(r"^/[^\x00-\x1f\x7f]*[^/]$")]


class ProjectRegistration(Record):
    schema_version: SchemaVersion
    kind: Literal["project-registration"]
    project_id: ProjectId
    created_at: Timestamp
    canonical_path: CanonicalPath
    object_format: Literal["sha1", "sha256"]
    supported_profiles: Annotated[list[Identifier], Field(min_length=1, max_length=8),
                                  AfterValidator(unique_list("supported_profiles"))]
    reviewer: Reviewer
    rationale: LongText
    scope: LongText
    confirmation: Annotated[ShortText, matches(r"^REGISTER prj-[0-9a-f]{16}$")]
