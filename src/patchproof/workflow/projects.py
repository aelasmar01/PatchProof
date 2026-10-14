"""`patchproof project add` and the project registry (PROJECT_SPEC.md 6 step 1, 9.1, 13.1; PP-009).

Registration validates the selected directory with the accepted PP-005 `register_repository`
(exact canonical root, its own real `.git`, owned by you, no alternates, worktrees, submodule
gitdirs, bare repositories, or the home directory or its ancestors), previews what PatchProof
will and will not read, and records the owner's explicit, typed approval. It reads no file
content, runs no repository code, changes nothing in the repository and approves nothing else.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final

from ..core.records import RecordError, load_record, validate_record
from ..core.records.project import ProjectRegistration
from ..git.command import GitBinary
from ..git.errors import SourceError
from ..git.repository import RegisteredRepository, register_repository
from ..pack_approval import ApprovalBlocked, Terminal, _ask, _ask_statement
from ..runner.profiles import PAPERTRAIL_PROFILE_ID, LoadedProfile
from ..runner.run_evidence import utc_stamp
from .safe_text import plain
from .store import PrivateStore, StoreError

MAX_PROJECT_BYTES: Final = 64 * 1024
SUPPORTED_PROFILES: Final = (PAPERTRAIL_PROFILE_ID,)


def project_id_for(canonical_path: str) -> str:
    return "prj-" + hashlib.sha256(canonical_path.encode("utf-8")).hexdigest()[:16]


def registration_phrase(project_id: str) -> str:
    return f"REGISTER {project_id}"


def check_registration(record: ProjectRegistration) -> None:
    """Semantic rules the schema cannot express."""
    if record.project_id != project_id_for(record.canonical_path):
        raise RecordError("project-registration", ["project_id is not derived from canonical_path"])
    if record.confirmation != registration_phrase(record.project_id):
        raise RecordError("project-registration", ["confirmation does not name this project"])


@dataclass(frozen=True)
class ProjectStore:
    root: Path

    def _store(self) -> PrivateStore:
        return PrivateStore(self.root, max_record_bytes=MAX_PROJECT_BYTES)

    def load(self, project_id: str) -> ProjectRegistration | None:
        raw = self._store().read(f"{project_id}.json")
        if raw is None:
            return None
        record = load_record(ProjectRegistration, raw, contract="project-registration", max_bytes=MAX_PROJECT_BYTES)
        check_registration(record)
        return record

    def save(self, record: ProjectRegistration) -> Path:
        check_registration(record)
        data = (record.model_dump_json(indent=2) + "\n").encode("utf-8")
        return self._store().write_once(f"{record.project_id}.json", data)

    def all(self) -> list[ProjectRegistration]:
        out = []
        for name in self._store().names():
            record = self.load(name.removesuffix(".json"))
            if record is not None:
                out.append(record)
        return out


def same_directory_as(root: Path, store: ProjectStore) -> str | None:
    """The ID of a registered project whose root is this same directory under another spelling, if any.

    PP-005 already refuses non-canonical spellings; this keeps one directory from holding two
    project identities even if an alias it does not know (a bind mount, say) were accepted.
    """
    st = os.lstat(root)
    for record in store.all():
        try:
            other = os.lstat(record.canonical_path)
        except OSError:
            continue
        if (other.st_dev, other.st_ino) == (st.st_dev, st.st_ino):
            return record.project_id
    return None


def render_registration(repo: RegisteredRepository, project_id: str, profile: LoadedProfile) -> str:
    scope = profile.profile.source_scope.include
    return "\n".join([
        "=" * 78,
        "PROJECT REGISTRATION: record your explicit approval of ONE local repository.",
        "=" * 78,
        "",
        f"Project ID        {project_id}   (derived from the canonical path)",
        f"Canonical root    {plain(repo.root, 1024)}",
        f"Object format     {repo.object_format.value}",
        f"Git client        {plain(repo.git.path, 300)} ({plain(repo.git.version_text, 80)})",
        f"Supported profile {profile.profile.profile_id} {profile.profile.profile_version} (the only executable "
        "v0.1 profile)",
        "",
        "What PatchProof will read from this repository, and only through the PP-005 Git wrapper:",
        "  - committed objects of revisions you name, resolved to full IDs and shown before use;",
        f"  - only files under the profile's source scope: {', '.join(scope)};",
        "  - into read-only private snapshots outside the repository.",
        "What it never does:",
        "  - read uncommitted edits, the working tree, the index, stashes, hooks or Git configuration;",
        "  - follow symlinks, include submodules, LFS pointers, '.git' paths, secret-looking paths (keys,",
        "    .env files, credentials) or files over the snapshot limits;",
        "  - write to the repository, check out, fetch, push, or run any repository code on the host.",
        "",
        "Registration approves nothing else: packs, plans and runs each need their own explicit step.",
        "",
    ]) + "\n"


def register_project(path: str, git: GitBinary, store: ProjectStore, terminal: Terminal, profile: LoadedProfile, *,
                     now: Callable[[], datetime], home: Path | None = None) -> int:
    """The interactive flow. 0 registered (or already registered, unchanged); 2 refused, nothing written."""
    try:
        repo = register_repository(path, git, home=home)
        project_id = project_id_for(str(repo.root))
        existing = store.load(project_id)
        if existing is not None:
            if existing.canonical_path != str(repo.root):
                raise ApprovalBlocked("the derived project ID is already registered for a different path")
            if existing.object_format != repo.object_format.value:
                raise ApprovalBlocked("this path is registered with a different object format; it cannot change")
            terminal.write(f"Already registered as {project_id}. Nothing was written.\n")
            return 0
        same = same_directory_as(repo.root, store)
        if same is not None:
            raise ApprovalBlocked(f"this repository directory is already registered as {same} under another path")
        terminal.write(render_registration(repo, project_id, profile))
        phrase = registration_phrase(project_id)
        identity = _ask(terminal, "Your name (asserted, not verified): ")
        rationale = _ask_statement(terminal, "Rationale for registering this repository: ", phrase)
        scope = _ask_statement(terminal, "Registration scope: ", phrase, differs_from=rationale)
        terminal.write(f"\nTo register, type exactly:  {phrase}\n")
        typed = terminal.read_line("Confirmation: ")
        if typed != phrase:
            raise ApprovalBlocked("the confirmation does not match the phrase")
        again = register_repository(path, git, home=home)
        if (again.root, again.object_format) != (repo.root, repo.object_format):
            raise ApprovalBlocked("the repository changed during the review")
        record = validate_record(ProjectRegistration, {
            "schema_version": "1.0", "kind": "project-registration", "project_id": project_id,
            "created_at": utc_stamp(now()),
            "canonical_path": str(repo.root), "object_format": repo.object_format.value,
            "supported_profiles": list(SUPPORTED_PROFILES),
            "reviewer": {"asserted_identity": identity, "basis": "local-assertion-unverified"},
            "rationale": rationale, "scope": scope, "confirmation": typed}, "project-registration")
        written = store.save(record)
        if store.load(project_id) != record or (os.lstat(written).st_mode & 0o777) != 0o400:
            terminal.write(f"\nFAILED VERIFICATION: the record at {plain(written, 1024)} did not read back as "
                           "written. It has not been deleted.\n")
            return 2
    except (SourceError, ApprovalBlocked, RecordError, StoreError, OSError) as exc:
        terminal.write(f"\nNOT REGISTERED: {plain(exc, 600)}. Nothing was written.\n")
        return 2
    except (EOFError, KeyboardInterrupt):
        terminal.write("\nNOT REGISTERED: input ended. Nothing was written.\n")
        return 2
    terminal.write(f"\nPROJECT REGISTERED: {project_id}\n  This approves reading committed revisions of this "
                   "repository only. It approves no pack, plan or run.\n")
    return 0
