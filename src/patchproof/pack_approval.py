"""Owner-operated approval of the PaperTrail verification pack (PP-008 integration utility).

This is NOT the general PP-009 CLI. It approves one pack, `papertrail-document-access`,
through the accepted PP-007 mechanism, and nothing else:
`BindingInputs` -> `create_approval` -> `ApprovalStore.save` -> `check_approval`. It adds no
record format, confirmation algorithm or store of its own.

Run it yourself, in your own terminal, from the project directory:

    uv run --locked --offline python -I -m patchproof.pack_approval

**What it does:**
1. Refuses to run with any argument, with any `PATCHPROOF*` environment variable, or unless
   standard input and output are a terminal and the process is in that terminal's
   foreground process group. A piped or redirected confirmation is never read.
2. Recomputes every binding from the source artifacts: the pack directory (static validation
   only; no pack module is imported), the versioned execution profile (strict loader, pinned
   hash), the private gate C2 collection evidence (pinned hashes, exact eight-test order),
   the approved verifier image and the verifier plugin version. The draft approval JSON is
   never read.
3. Shows the complete binding set, the full profile, the security claim, the functional
   controls and the limitations; then asks for the reviewer's asserted identity, rationale,
   scope and the exact PP-007 confirmation phrase.
4. Recomputes all bindings again, and re-reads the store, immediately before writing. Any
   change aborts with nothing written.
5. Writes one immutable record, reads it back, and confirms with `check_approval` that it is
   the pack's current approval for exactly the recomputed bindings.

**Limits:** the terminal checks are a procedural control, not proof of a human. Anything
running as the same OS account can allocate a pseudo-terminal, and the reviewer identity is
a local assertion (`local-assertion-unverified`). A pack approval does not authorize a run;
run authorization is a separate, later record.
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
import stat
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Protocol

from platformdirs import user_data_path

from .core.approvals import (
    MAX_RECORD_BYTES,
    ApprovalError,
    ApprovalStore,
    BindingInputs,
    ReviewDecision,
    check_approval,
    confirmation_phrase,
    create_approval,
    current_approval,
)
from .core.records import RecordError
from .core.records.pack import ApprovalBindings, ApprovalRecord, CollectedTest
from .core.strict_json import StrictJsonError, loads_strict
from .packs.collection import COLLECTION_OUTPUT_CAP, CollectionMismatch, parse_collected, review_collection
from .packs.validation import PackError, ValidatedPack, validate_pack
from .runner.policy import PolicyViolation
from .runner.profiles import (
    PAPERTRAIL_PROFILE_ID,
    PAPERTRAIL_PROFILE_SHA256,
    PAPERTRAIL_PROFILE_VERSION,
    LoadedProfile,
    ProfileError,
    load_profile,
    profile_document,
    profile_path,
)
from .runner.run_plan import APPROVED_RUN_IMAGES, PLUGIN_VERSION, ApprovedRunImage
from .runner.run_policy import PACK_MOUNT, RunRole, collect_command

APP_NAME: Final = "PatchProof"
PAPERTRAIL_PACK_ID: Final = "papertrail-document-access"
PAPERTRAIL_PACK_VERSION: Final = "1.0.0"
# Gate C2 collection evidence (2026-10-13), kept privately. Review-controlled identities.
C2_STDOUT_SHA256: Final = "sha256:c9e5489569a02050345f935bd20c61a604ccd824af26fc47ef5f4e645a9d9ee5"
C2_RESULT_SHA256: Final = "sha256:9b721cda80fe6b98285204d92fe377a2252b661d21ec9f5b352e8debe67264ff"
MAX_RESULT_BYTES: Final = 65536
MAX_TEXT_INPUT: Final = 4000
# Owner follow-up from PP-008 (2026-10-14): a rationale or scope must say something. These
# rules check effort, not truth; they apply when a statement is typed, never to stored records.
MIN_STATEMENT_CHARS: Final = 20
MIN_STATEMENT_WORDS: Final = 4
PLACEHOLDER_WORDS: Final = frozenset({
    "idk", "test", "tests", "testing", "todo", "tbd", "na", "n/a", "none", "nothing", "asdf", "qwerty", "ok",
    "okay", "yes", "no", "foo", "bar", "baz", "placeholder", "whatever", "stuff", "something", "x", "xx", "xxx",
    "lorem", "ipsum", "blah", "etc", "dunno", "sure", "fine", "same",
})
_WORD_RE: Final = re.compile(r"[a-z0-9][a-z0-9'/_-]*")
_LONG_HEX_RE: Final = re.compile(r"[0-9a-f]{40,}")

# What each check witnesses (pack README, reviewed in the PP-008 readiness review).
CHECK_SUMMARIES: Final = {
    "AUTH-001": "bob -> doc-alice-private. VIOLATION only if Alice's protected marker is in the body and the "
                "fixture shows bob is neither owner nor a granted role. SECURE only on 403/404 with no marker "
                "and no content.",
    "AUTH-002": "no credential -> doc-alice-private. VIOLATION only if the marker is in the body. SECURE only "
                "on 401 with no marker and no content.",
    "AUTH-003": "carol (auditor) -> doc-bob-private, which lists no reader roles. VIOLATION only if Bob's "
                "marker is in the body. SECURE only on 403/404 with no marker and no content.",
    "AUTH-004": "forged bearer token -> doc-alice-private. VIOLATION only if the marker is in the body. "
                "SECURE only on 401 with no marker and no content.",
    "FUNC-001": "Alice (owner) receives exactly her document: ID, owner and content equal the fixture.",
    "FUNC-002": "Carol receives Alice's document, which explicitly grants the auditor role.",
    "FUNC-003": "Bob (owner) receives exactly his document.",
    "FUNC-004": "Alice's /me returns her own user ID and role and does not echo her token.",
}


class ApprovalBlocked(Exception):
    """A prerequisite failed. Nothing was approved."""


@dataclass(frozen=True)
class ApprovalTarget:
    """Every source artifact the bindings are recomputed from."""

    pack_dir: Path
    pack_id: str
    pack_version: str
    profile_path: Path
    profile_sha256: str
    evidence_dir: Path
    evidence_stdout_sha256: str
    evidence_result_sha256: str
    plugin_source: Path
    approved_images: tuple[ApprovedRunImage, ...] = APPROVED_RUN_IMAGES


def project_root() -> Path:
    """The source checkout this module runs from (src/patchproof/pack_approval.py)."""
    return Path(os.path.realpath(__file__)).parents[2]


def data_root() -> Path:
    return user_data_path(APP_NAME, appauthor=False, ensure_exists=False)


def approval_store_root() -> Path:
    """The private approval store: <user data>/PatchProof/approvals (macOS: ~/Library/Application Support)."""
    return data_root() / "approvals"


def papertrail_target() -> ApprovalTarget:
    root = project_root()
    return ApprovalTarget(
        pack_dir=root / "examples" / "packs" / PAPERTRAIL_PACK_ID, pack_id=PAPERTRAIL_PACK_ID,
        pack_version=PAPERTRAIL_PACK_VERSION,
        profile_path=profile_path(root, PAPERTRAIL_PROFILE_ID, PAPERTRAIL_PROFILE_VERSION),
        profile_sha256=PAPERTRAIL_PROFILE_SHA256, evidence_dir=data_root() / "evidence" / "pp-008-gate-c" / "C2",
        evidence_stdout_sha256=C2_STDOUT_SHA256, evidence_result_sha256=C2_RESULT_SHA256,
        plugin_source=root / "verifier" / "patchproof_verifier" / "plugin.py")


# ------------------------------------------------------------------ interactive gate


class NotInteractive(Exception):
    """The process is not an owner at a foreground terminal. Nothing is read or written."""


def require_interactive(argv: Sequence[str], environ: Mapping[str, str], *, stdin_fd: int = 0,
                        stdout_fd: int = 1) -> None:
    if len(argv) > 1:
        raise NotInteractive("this command takes no arguments; every answer is typed at the terminal")
    require_terminal(environ, stdin_fd=stdin_fd, stdout_fd=stdout_fd)


def require_terminal(environ: Mapping[str, str], *, stdin_fd: int = 0, stdout_fd: int = 1) -> None:
    """The terminal part of the gate, for `patchproof` subcommands whose arguments only select an object."""
    if any(name.upper().startswith("PATCHPROOF") for name in environ):
        raise NotInteractive("PATCHPROOF* environment variables are not accepted; unset them and retry")
    if not (os.isatty(stdin_fd) and os.isatty(stdout_fd)):
        raise NotInteractive("standard input and output must be an interactive terminal (no pipes or files)")
    try:
        foreground = os.tcgetpgrp(stdin_fd) == os.getpgrp()
    except OSError:
        foreground = False
    if not foreground:
        raise NotInteractive("standard input must be this process's controlling terminal, in the foreground")


class Terminal(Protocol):
    def write(self, text: str) -> None: ...

    def read_line(self, prompt: str) -> str: ...


class _ConsoleTerminal:
    def write(self, text: str) -> None:
        sys.stdout.write(text)
        sys.stdout.flush()

    def read_line(self, prompt: str) -> str:
        return input(prompt)


# ------------------------------------------------------------------ binding assembly


@dataclass(frozen=True)
class Review:
    pack: ValidatedPack
    profile: LoadedProfile
    collection: tuple[CollectedTest, ...]
    inputs: BindingInputs
    bindings: ApprovalBindings
    phrase: str


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _read_private(directory: Path, name: str, limit: int) -> bytes:
    raw = str(directory)
    if not os.path.isabs(raw) or os.path.realpath(raw) != raw:
        raise ApprovalBlocked("collection evidence directory must be absolute and canonical")
    try:
        dir_fd = os.open(raw, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise ApprovalBlocked("collection evidence directory is missing or not a directory") from exc
    try:
        st = os.fstat(dir_fd)
        if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
            raise ApprovalBlocked("collection evidence directory must be private (0700) and owned by you")
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
        except OSError as exc:
            raise ApprovalBlocked(f"collection evidence {name} is missing or a symlink") from exc
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise ApprovalBlocked(f"collection evidence {name} is not a regular file")
            data = handle.read(limit + 1)
    finally:
        os.close(dir_fd)
    if len(data) > limit:
        raise ApprovalBlocked(f"collection evidence {name} exceeds its size limit")
    return data


def _plugin_version(source: Path) -> str:
    """PLUGIN_VERSION as written in the verifier plugin source. Parsed with `ast`; never imported."""
    try:
        tree = ast.parse(source.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, SyntaxError) as exc:
        raise ApprovalBlocked("verifier plugin source is missing or unreadable") from exc
    for node in tree.body:
        if (isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
                and node.target.id == "PLUGIN_VERSION" and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            return node.value.value
    raise ApprovalBlocked("verifier plugin source does not declare PLUGIN_VERSION")


def _check_collection_evidence(target: ApprovalTarget, pack: ValidatedPack, verifier_image: str
                               ) -> tuple[CollectedTest, ...]:
    stdout = _read_private(target.evidence_dir, "stdout.bin", COLLECTION_OUTPUT_CAP)
    result_raw = _read_private(target.evidence_dir, "result.json", MAX_RESULT_BYTES)
    if _sha256(stdout) != target.evidence_stdout_sha256:
        raise ApprovalBlocked("collection output differs from the recorded C2 evidence hash")
    if _sha256(result_raw) != target.evidence_result_sha256:
        raise ApprovalBlocked("collection result differs from the recorded C2 evidence hash")
    try:
        collected = parse_collected(stdout)
        ordered = review_collection(pack.manifest.tests, collected)
        result = loads_strict(result_raw, max_bytes=MAX_RESULT_BYTES)
    except (CollectionMismatch, StrictJsonError) as exc:
        raise ApprovalBlocked(f"collection evidence is invalid: {exc}") from None
    if [(c.id, c.nodeid) for c in ordered] != [(t.id, t.nodeid) for t in pack.manifest.tests]:
        raise ApprovalBlocked("collected order differs from the manifest order")
    if not isinstance(result, dict):
        raise ApprovalBlocked("collection result is not an object")
    test_paths = tuple(f"{PACK_MOUNT}/{rel}" for rel in pack.test_files)
    facts = result.get("facts")
    expected = {
        "step": "C2", "synthetic": False, "verdict": "PASS", "exit_code": 0, "termination": "EXITED",
        "timed_out": False, "stdout_truncated": False, "oom_killed": False, "gate_passed": True,
        "pack_verified_before": True, "pack_verified_after": True, "image": verifier_image,
        "pack_tree_sha256": pack.pack_tree_sha256, "manifest_sha256": pack.manifest_sha256,
        "stdout_bytes": len(stdout), "command": list(collect_command(test_paths)),
    }
    wrong = sorted(k for k, v in expected.items() if result.get(k) != v or type(result.get(k)) is not type(v))
    if not isinstance(facts, dict) or facts.get("collected") != [c.model_dump() for c in ordered]:
        wrong.append("facts.collected")
    if wrong:
        raise ApprovalBlocked(f"collection result does not establish this pack's collection: {', '.join(wrong)}")
    return ordered


def assemble_review(target: ApprovalTarget) -> Review:
    """Recompute every binding from its source artifact. Raises ApprovalBlocked."""
    try:
        pack = validate_pack(target.pack_dir)
    except PackError as exc:
        raise ApprovalBlocked(f"pack is invalid: {exc}") from None
    if (pack.manifest.pack_id, pack.manifest.pack_version) != (target.pack_id, target.pack_version):
        raise ApprovalBlocked("pack ID or version differs from the pack this command approves")
    try:
        profile = load_profile(target.profile_path, expected_sha256=target.profile_sha256,
                               approved_images=target.approved_images)
    except ProfileError as exc:
        raise ApprovalBlocked(f"execution profile: {exc}") from None
    if profile.profile.fixture_contract != pack.manifest.fixture_contract:
        raise ApprovalBlocked("pack and profile name different fixture contracts")
    verifier = [a for a in target.approved_images if a.role is RunRole.VERIFIER]
    if [a.image.value for a in verifier] != [profile.profile.verifier_image_id]:
        raise ApprovalBlocked("the verifier image is not the single approved verifier run image")
    plugin_version = _plugin_version(target.plugin_source)
    if plugin_version != PLUGIN_VERSION:
        raise ApprovalBlocked(f"verifier plugin source declares {plugin_version}, the runner expects "
                              f"{PLUGIN_VERSION}")
    collection = _check_collection_evidence(target, pack, profile.profile.verifier_image_id)
    inputs = BindingInputs(
        pack_id=pack.manifest.pack_id, pack_version=pack.manifest.pack_version,
        manifest_sha256=pack.manifest_sha256, pack_tree_sha256=pack.pack_tree_sha256, collection=collection,
        verifier_image_id=profile.profile.verifier_image_id, verifier_plugin_version=plugin_version,
        profile_id=profile.profile.profile_id, profile_sha256=profile.sha256)
    try:
        bindings = inputs.bindings()
    except RecordError as exc:
        raise ApprovalBlocked(f"bindings are invalid: {exc}") from None
    return Review(pack=pack, profile=profile, collection=collection, inputs=inputs, bindings=bindings,
                  phrase=confirmation_phrase(bindings))


# ------------------------------------------------------------------ approval store


def provision_store(root: Path) -> ApprovalStore:
    """Create (once) and open the private approval directory. Never follows or repairs anything.

    The parent must already exist as a canonical directory owned by you and not writable by
    others. The store is created with `mkdir(0700)` relative to the parent's descriptor; an
    existing store must already be exactly 0700. The opened store's identity must equal the
    directory checked here.
    """
    parent = root.parent
    if not os.path.isabs(str(root)) or os.path.realpath(str(parent)) != str(parent):
        raise ApprovalBlocked("approval store parent must be an absolute canonical directory")
    try:
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise ApprovalBlocked("approval store parent is missing, not a directory, or a symlink") from exc
    try:
        pst = os.fstat(parent_fd)
        if pst.st_uid != os.getuid() or stat.S_IMODE(pst.st_mode) & 0o022:
            raise ApprovalBlocked("approval store parent must be owned by you and not writable by others")
        try:
            os.mkdir(root.name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        st = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
    finally:
        os.close(parent_fd)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
        raise ApprovalBlocked("approval store must be a directory owned by you with mode 0700")
    try:
        store = ApprovalStore(root)
    except ApprovalError as exc:
        raise ApprovalBlocked(f"approval store: {exc}") from None
    if store.identity != (st.st_dev, st.st_ino):
        raise ApprovalBlocked("approval store was replaced while it was being opened")
    return store


# ------------------------------------------------------------------ review screen


def render_review(review: Review, current: ApprovalRecord | None, store_root: Path) -> str:
    b = review.bindings
    manifest = review.pack.manifest
    kinds = {t.id: t for t in manifest.tests}
    lines = [
        "=" * 78,
        "PACK APPROVAL REVIEW: this approves a verification pack. It is NOT a run authorization.",
        "=" * 78,
        "",
        "Bindings (recomputed now from the source artifacts):",
        f"  pack_id                  {b.pack_id}",
        f"  pack_version             {b.pack_version}",
        f"  pack_schema_version      {b.pack_schema_version}",
        f"  manifest_sha256          {b.manifest_sha256}",
        f"  pack_tree_sha256         {b.pack_tree_sha256}",
        f"  verifier_image_id        {b.verifier_image_id}",
        f"  verifier_plugin_version  {b.verifier_plugin_version}",
        f"  profile_id               {b.profile_id}",
        f"  profile_sha256           {b.profile_sha256}",
        f"  fixture contract         {manifest.fixture_contract} (pack copy hash-checked against the reviewed "
        "contract)",
        "",
        f"Expected collection ({len(b.expected_collection)} tests, collected in the verifier image at gate C2, "
        "in this order):",
    ]
    for c in b.expected_collection:
        t = kinds[c.id]
        lines.append(f"  {c.id:9} {t.kind:10} baseline {t.baseline_expected:19} candidate {t.candidate_expected:6}"
                     f"  {c.nodeid}")
    lines += ["", "Security claim (pack expectation):", f"  {manifest.expectation}", "",
              "Unauthorized-disclosure witnesses and functional controls:"]
    for c in b.expected_collection:
        lines.append(f"  {c.id}: {CHECK_SUMMARIES.get(c.id, '(no reviewed summary for this test ID)')}")
    lines += [
        "  Anything else (a 200 without the marker, a 5xx, an unparseable body) is INCONCLUSIVE, never SECURE",
        "  or a violation. A deny-everything change fails the functional controls.",
        "",
        f"Execution profile {review.profile.profile.profile_id} {review.profile.profile.profile_version} "
        f"({review.profile.path}):",
        *("  " + line for line in profile_document(review.profile).splitlines()),
        "",
        "Limits of this approval:",
        "  - No vulnerability has been reproduced. Neither PaperTrail revision has been run; no application",
        "    behavior has been observed. Collection only proved the eight tests load in the verifier image.",
        "  - The claim covers these eight checks against the fixed synthetic fixture, one pair, at",
        "    127.0.0.1:8080. It says nothing about other endpoints, data, or authorization paths.",
        "  - It authorizes no run. A comparison needs a separate run authorization naming the source",
        "    snapshots, the container budget and the plan.",
        "  - Reviewer identity is a local assertion (basis local-assertion-unverified). This terminal",
        "    check is a procedural control, not proof that a human typed the answers.",
        "  - Changing any binding above makes this approval stale; it is never refreshed silently.",
        "",
        f"Approval store: {store_root}",
        f"Supersedes: {current.approval_id if current else 'nothing (no earlier approval of this pack)'}",
        "",
    ]
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ the approval flow


def _ask(terminal: Terminal, prompt: str) -> str:
    answer = terminal.read_line(prompt).strip()
    if not answer or len(answer) > MAX_TEXT_INPUT:
        raise ApprovalBlocked(f"an answer to {prompt.strip()!r} is required (at most {MAX_TEXT_INPUT} characters)")
    return answer


def _folded(text: str) -> str:
    return " ".join(text.split()).casefold()


def statement_problem(answer: str, phrase: str, *, differs_from: str | None = None) -> str | None:
    """Why a typed rationale or scope is not acceptable, or None. Pure."""
    folded = _folded(answer)
    copied = [t for t in _LONG_HEX_RE.findall(_folded(phrase)) if t in folded]
    if _folded(phrase) in folded or copied:
        return ("contains the confirmation phrase or its hash; describe the review in your own words and type "
                "the phrase only at the confirmation prompt")
    words = set(_WORD_RE.findall(folded))
    meaningful = {w for w in words if len(w) > 1 and w not in PLACEHOLDER_WORDS}
    if (len(folded) < MIN_STATEMENT_CHARS or len(words) < MIN_STATEMENT_WORDS
            or len(meaningful) < MIN_STATEMENT_WORDS - 1):
        return (f"is not a substantive statement; write at least {MIN_STATEMENT_CHARS} characters and "
                f"{MIN_STATEMENT_WORDS} different words saying what you reviewed and why (placeholders such as "
                "'idk' or 'test' are refused)")
    if differs_from is not None and folded == _folded(differs_from):
        return "repeats the rationale; state the scope separately"
    return None


def _ask_statement(terminal: Terminal, prompt: str, phrase: str, *, differs_from: str | None = None) -> str:
    """A rationale or scope: substantive, never the confirmation phrase, and a scope is not the rationale."""
    answer = _ask(terminal, prompt)
    problem = statement_problem(answer, phrase, differs_from=differs_from)
    if problem:
        raise ApprovalBlocked(f"the answer to {prompt.strip()!r} {problem}")
    return answer


def run_approval(target: ApprovalTarget, store_root: Path, terminal: Terminal, *,
                 now: Callable[[], datetime]) -> int:
    """The interactive flow. Returns 0 only when a verified approval was written."""
    written: Path | None = None
    try:
        review = assemble_review(target)
        store = provision_store(store_root)
        history = store.records()
        current = current_approval(history.values(), review.bindings.pack_id)
        already = check_approval(history.values(), review.inputs)
        if already.status == "APPROVED":
            terminal.write(f"{already.approval_id} already approves exactly these bindings. Nothing was written.\n")
            return 3
        terminal.write(render_review(review, current, store_root))
        identity = _ask(terminal, "Your name (asserted, not verified): ")
        rationale = _ask_statement(terminal, "Rationale for approving this pack: ", review.phrase)
        scope = _ask_statement(terminal, "Approval scope: ", review.phrase, differs_from=rationale)
        terminal.write(f"\nTo approve, type exactly:  {review.phrase}\n")
        typed = terminal.read_line("Confirmation: ")
        if typed != review.phrase:
            raise ApprovalBlocked("the confirmation does not match the phrase")

        fresh = assemble_review(target)
        if fresh.bindings != review.bindings:
            raise ApprovalBlocked("a binding changed between review and confirmation")
        if store.records() != history:
            raise ApprovalBlocked("the approval store changed during the review")
        record = create_approval(fresh.bindings, ReviewDecision(identity, rationale, scope, typed),
                                 supersedes=current, now=now())
        written = store.save(record)

        after = store.records()
        problems = []
        if after.get(record.approval_id) != record:
            problems.append("the record read back differs from the record written")
        if any(after.get(k) != v for k, v in history.items()) or set(after) != set(history) | {record.approval_id}:
            problems.append("the earlier approval history is not intact")
        if stat.S_IMODE(os.lstat(written).st_mode) != 0o400:
            problems.append("the record file is not read-only")
        final = check_approval(after.values(), assemble_review(target).inputs, approval_id=record.approval_id)
        if final.status != "APPROVED":
            problems.append(f"check_approval reports {final.status} {list(final.stale_fields)}")
        if problems:
            terminal.write(f"\nFAILED VERIFICATION. A record was written at {written}, but it is NOT a valid "
                           f"approval: {'; '.join(problems)}. It has not been deleted (records are immutable).\n")
            return 4
    except (ApprovalBlocked, ApprovalError, RecordError, PolicyViolation, OSError) as exc:
        if written:
            terminal.write(f"\nFAILED VERIFICATION: {exc}. A record was written at {written}, but it was not "
                           "verified as a valid approval. It has not been deleted (records are immutable).\n")
            return 4
        terminal.write(f"\nNOT APPROVED: {exc}. Nothing was written.\n")
        return 2
    except (EOFError, KeyboardInterrupt):
        terminal.write("\nNOT APPROVED: input ended. Nothing was written.\n")
        return 2
    terminal.write(f"\nPACK APPROVED: {record.approval_id}\n  record {written}\n  reviewer "
                   f"{record.reviewer.asserted_identity} (local assertion)\n  This approves the pack only. "
                   "It authorizes no run.\n")
    return 0


# ------------------------------------------------------------------ supersession (owner-operated)


def _record_bytes(store: ApprovalStore) -> dict[str, tuple[bytes, int]]:
    """Raw bytes and permission bits of every record file, read through the pinned store directory.

    Used only to prove that existing records are byte-for-byte unchanged by a supersession.
    The store's own reader has already validated each entry; this adds no parsing.
    """
    try:
        dir_fd = os.open(store.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise ApprovalBlocked("approval store is missing, not a directory, or a symlink") from exc
    try:
        st = os.fstat(dir_fd)
        if (st.st_dev, st.st_ino) != store.identity:
            raise ApprovalBlocked("approval store was replaced")
        found: dict[str, tuple[bytes, int]] = {}
        for name in sorted(os.listdir(dir_fd)):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
            with os.fdopen(fd, "rb") as handle:
                fst = os.fstat(handle.fileno())
                if not stat.S_ISREG(fst.st_mode):
                    raise ApprovalBlocked(f"{name} is not a regular file")
                found[name] = (handle.read(MAX_RECORD_BYTES + 1), stat.S_IMODE(fst.st_mode))
        return found
    finally:
        os.close(dir_fd)


def render_current(record: ApprovalRecord) -> str:
    return "\n".join([
        "=" * 78,
        "SUPERSEDE THE CURRENT APPROVAL: the existing record is kept, unchanged and readable. The new",
        "record names it in `supersedes`; from then on the new record is the current approval and the",
        "existing one is history. Nothing is deleted, edited or renamed.",
        "=" * 78,
        "",
        "Current approval (as stored):",
        f"  approval_id   {record.approval_id}",
        f"  created_at    {record.created_at}",
        f"  supersedes    {record.supersedes or 'nothing'}",
        f"  reviewer      {record.reviewer.asserted_identity} ({record.reviewer.basis})",
        f"  rationale     {record.rationale!r}",
        f"  scope         {record.scope!r}",
        "",
        "Supersession is allowed only while every binding is unchanged: the new record approves",
        "exactly the same pack, collection, verifier and profile, with a new rationale and scope.",
        "",
    ]) + "\n"


def run_supersession(target: ApprovalTarget, store_root: Path, terminal: Terminal, *,
                     now: Callable[[], datetime]) -> int:
    """Replace the current approval's reviewer statement by supersession.

    Returns 0 only when the replacement was written and verified, the original records are
    byte-for-byte unchanged, and the original is superseded. 2: nothing written. 4: a record
    was written but failed verification (it is reported, never deleted).
    """
    written: Path | None = None
    try:
        review = assemble_review(target)
        try:
            os.lstat(store_root)
        except OSError:
            raise ApprovalBlocked("there is no approval store, so there is nothing to supersede") from None
        store = provision_store(store_root)
        history = store.records()
        original_bytes = _record_bytes(store)
        current = current_approval(history.values(), review.bindings.pack_id)
        if current is None:
            raise ApprovalBlocked("this pack has no current approval to supersede")
        status = check_approval(history.values(), review.inputs, approval_id=current.approval_id)
        if status.status != "APPROVED":
            raise ApprovalBlocked(f"the current approval is {status.status} {list(status.stale_fields)}; a stale "
                                  "approval cannot be superseded with a new statement. Review the changed bindings "
                                  "and approve them with patchproof.pack_approval instead")
        terminal.write(render_current(current))
        terminal.write(render_review(review, current, store_root))
        identity = _ask(terminal, "Your name (asserted, not verified): ")
        rationale = _ask_statement(terminal, "Rationale for approving this pack: ", review.phrase)
        scope = _ask_statement(terminal, "Approval scope: ", review.phrase, differs_from=rationale)
        terminal.write(f"\nThis supersedes {current.approval_id}. To approve, type exactly:  {review.phrase}\n")
        typed = terminal.read_line("Confirmation: ")
        if typed != review.phrase:
            raise ApprovalBlocked("the confirmation does not match the phrase")

        fresh = assemble_review(target)
        if fresh.bindings != review.bindings:
            raise ApprovalBlocked("a binding changed between review and confirmation")
        if store.records() != history or _record_bytes(store) != original_bytes:
            raise ApprovalBlocked("the approval store changed during the review")
        record = create_approval(fresh.bindings, ReviewDecision(identity, rationale, scope, typed),
                                 supersedes=current, now=now())
        written = store.save(record)

        after = store.records()
        after_bytes = _record_bytes(store)
        problems = []
        if any(after_bytes.get(name) != value for name, value in original_bytes.items()):
            problems.append("an existing record is no longer byte-for-byte identical")
        if set(after) != set(history) | {record.approval_id}:
            problems.append("the approval history is not exactly the earlier history plus the new record")
        if after.get(record.approval_id) != record:
            problems.append("the record read back differs from the record written")
        if stat.S_IMODE(os.lstat(written).st_mode) != 0o400:
            problems.append("the record file is not read-only")
        inputs = assemble_review(target).inputs
        new_status = check_approval(after.values(), inputs, approval_id=record.approval_id)
        if new_status.status != "APPROVED":
            problems.append(f"the replacement is {new_status.status} {list(new_status.stale_fields)}")
        old_status = check_approval(after.values(), inputs, approval_id=current.approval_id)
        if (old_status.status, old_status.stale_fields) != ("APPROVAL_STALE", ("superseded",)):
            problems.append(f"the original is {old_status.status}, not superseded")
        if record.supersedes != current.approval_id:
            problems.append("the replacement does not name the original in supersedes")
        if problems:
            terminal.write(f"\nFAILED VERIFICATION. A record was written at {written}, but the supersession is NOT "
                           f"verified: {'; '.join(problems)}. Nothing has been deleted (records are immutable).\n")
            return 4
    except (ApprovalBlocked, ApprovalError, RecordError, PolicyViolation, OSError) as exc:
        if written:
            terminal.write(f"\nFAILED VERIFICATION: {exc}. A record was written at {written}, but the supersession "
                           "was not verified. Nothing has been deleted (records are immutable).\n")
            return 4
        terminal.write(f"\nNOT SUPERSEDED: {exc}. Nothing was written; the current approval is unchanged.\n")
        return 2
    except (EOFError, KeyboardInterrupt):
        terminal.write("\nNOT SUPERSEDED: input ended. Nothing was written; the current approval is unchanged.\n")
        return 2
    terminal.write(f"\nPACK APPROVAL SUPERSEDED.\n  new current approval  {record.approval_id}\n"
                   f"    record {written}\n  superseded (kept)     {current.approval_id}\n"
                   f"  reviewer {record.reviewer.asserted_identity} (local assertion)\n"
                   "  Every binding is unchanged. This approves the pack only. It authorizes no run.\n")
    return 0


def main_supersede() -> int:
    try:
        require_interactive(sys.argv, os.environ)
    except NotInteractive as exc:
        sys.stderr.write(f"NOT SUPERSEDED: {exc}. Nothing was read or written.\n")
        return 2
    return run_supersession(papertrail_target(), approval_store_root(), _ConsoleTerminal(),
                            now=lambda: datetime.now(UTC))


def main() -> int:
    try:
        require_interactive(sys.argv, os.environ)
    except NotInteractive as exc:
        sys.stderr.write(f"NOT APPROVED: {exc}. Nothing was read or written.\n")
        return 2
    return run_approval(papertrail_target(), approval_store_root(), _ConsoleTerminal(), now=lambda: datetime.now(UTC))


if __name__ == "__main__":
    raise SystemExit(main())
