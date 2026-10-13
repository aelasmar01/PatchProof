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
import stat
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Protocol

from platformdirs import user_data_path

from .core.approvals import (
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
        rationale = _ask(terminal, "Rationale for approving this pack: ")
        scope = _ask(terminal, "Approval scope: ")
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


def main() -> int:
    try:
        require_interactive(sys.argv, os.environ)
    except NotInteractive as exc:
        sys.stderr.write(f"NOT APPROVED: {exc}. Nothing was read or written.\n")
        return 2
    return run_approval(papertrail_target(), approval_store_root(), _ConsoleTerminal(), now=lambda: datetime.now(UTC))


if __name__ == "__main__":
    raise SystemExit(main())
