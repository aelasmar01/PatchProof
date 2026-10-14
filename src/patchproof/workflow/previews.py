"""`patchproof profile prepare` and `patchproof pack validate` (PROJECT_SPEC.md 7, 10.4, 13.1; PP-009).

Both are read-only previews:
- **Profile:** the versioned profile through the accepted strict loader, pinned to its reviewed
  hash, with its images, limits and deadlines. v0.1 has no image building, pulling or
  dependency installation: the reviewed r2 images were prepared at PP-008 gate B. With
  `--check-images`, the two approved image IDs are looked up locally by exact ID through the
  accepted Docker client's read-only `image inspect`; nothing is pulled, built or changed.
- **Pack:** the accepted PP-007 static validation (no pack module is imported, no target code
  runs) and, for the PaperTrail pack, its current approval state from the accepted store.
  Validation never approves a pack.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from ..core.approvals import ApprovalError, ApprovalStore, check_approval
from ..core.strict_json import StrictJsonError, loads_strict
from ..pack_approval import ApprovalBlocked, ApprovalTarget, Terminal, assemble_review
from ..packs.validation import PackError, ValidatedPack, validate_pack
from ..runner.docker_cli import Executor, ImageInspect
from ..runner.policy import ImageId, PolicyViolation
from ..runner.profiles import ProfileError, load_profile, profile_document
from ..runner.run_plan import APPROVED_RUN_IMAGES, ApprovedRunImage
from . import exit_codes
from .preflight import Preflight
from .safe_text import plain


def prepare_profile(path: Path, target: ApprovalTarget, terminal: Terminal, *,
                    executor_factory: Callable[[], Executor] | None = None,
                    images: tuple[ApprovedRunImage, ...] = APPROVED_RUN_IMAGES) -> int:
    pre = Preflight()
    try:
        loaded = load_profile(path, expected_sha256=target.profile_sha256)
    except (ProfileError, OSError) as exc:
        pre.mandatory("profile is the reviewed versioned profile (strict loader, pinned hash)", False, str(exc))
        terminal.write(pre.render())
        terminal.write("\nPROFILE NOT PREPARED: only the reviewed PaperTrail profile is supported in v0.1.\n")
        return exit_codes.BLOCKED
    p = loaded.profile
    pre.mandatory("profile is the reviewed versioned profile (strict loader, pinned hash)", True, loaded.sha256)
    approved = {a.role.value: a.image.value for a in images}
    pre.mandatory("profile images are the approved run images",
                  (p.target_image_id, p.verifier_image_id) == (approved.get("target"), approved.get("verifier")))
    if executor_factory is not None:
        executor = executor_factory()
        for role, image in sorted(approved.items()):
            try:
                result = executor.run(ImageInspect(ImageId(image)))
                found = loads_strict(result.stdout) if result.ok else None
                ok = isinstance(found, list) and len(found) == 1 and found[0].get("Id") == image
            except (StrictJsonError, PolicyViolation, OSError, AttributeError):
                ok = False
            pre.mandatory(f"DOCKER INTERACTION (read-only `docker image inspect`, never pulled): {role} image "
                          "present locally with its exact ID", ok, image)
    else:
        pre.diagnostic("local image presence NOT CHECKED (no Docker interaction)", False,
                       "use --check-images for a read-only Docker lookup")
    terminal.write("\n".join([
        "=" * 78, "EXECUTION PROFILE PREVIEW (read-only)", "=" * 78, "",
        f"Profile        {p.profile_id} {p.profile_version}  {loaded.sha256}",
        f"Target image   {p.target_image_id}", f"Verifier image {p.verifier_image_id}", "",
        *profile_document(loaded).splitlines(), "",
        "Preparation in v0.1: none is performed. The reviewed r2 images were prepared and approved at PP-008",
        "gate B. This command never pulls, builds or installs anything and needs no internet access.", "",
        pre.render()]))
    return exit_codes.OK if pre.passed else exit_codes.BLOCKED


def _render_pack(pack: ValidatedPack) -> list[str]:
    m = pack.manifest
    lines = [
        f"Pack           {m.pack_id} {m.pack_version}: {plain(m.title, 200)}",
        f"  manifest     {pack.manifest_sha256}", f"  tree         {pack.pack_tree_sha256}",
        f"  adapter      {m.adapter}; fixture contract {m.fixture_contract}",
        f"  repetitions  {m.repetitions.pairs} pair(s); seed policy {m.repetitions.fixture_seed_policy}",
        f"  limits       response {m.limits.max_response_bytes} B; per case {m.limits.case_timeout_seconds} s",
        f"Expectation    {plain(m.expectation, 1000)}", "",
        "Required tests and declared observations (declarations, not results):",
    ]
    for t in m.tests:
        lines.append(f"  {t.id:9} {t.kind:10} baseline {t.baseline_expected:19} candidate {t.candidate_expected:6} "
                     f"{t.nodeid}")
    lines += ["", f"Files ({len(pack.files)}):"]
    lines += [f"  {f.sha256}  {f.size:>7} B  {plain(f.path, 255)}" for f in pack.files]
    return lines


def validate_pack_preview(pack_dir: Path, target: ApprovalTarget, approval_store: Path, terminal: Terminal) -> int:
    pre = Preflight()
    try:
        pack = validate_pack(pack_dir)
    except (PackError, OSError) as exc:
        pre.mandatory("pack passes static validation (no module imported, no target code run)", False,
                      plain(exc, 400))
        terminal.write(pre.render())
        terminal.write("\nPACK INVALID. Nothing was approved.\n")
        return exit_codes.BLOCKED
    pre.mandatory("pack passes static validation (no module imported, no target code run)", True,
                  pack.pack_tree_sha256)
    status = "not a reviewed pack: v0.1 can approve and execute only the PaperTrail pack"
    if pack.manifest.pack_id == target.pack_id:
        try:
            review = assemble_review(target)
            if review.pack.pack_tree_sha256 != pack.pack_tree_sha256:
                status = "differs from the reviewed PaperTrail pack directory; any approval would be stale"
            elif not approval_store.exists():
                status = "NOT APPROVED (no approval store)"
            else:
                history = ApprovalStore(approval_store).records()
                check = check_approval(history.values(), review.inputs)
                status = f"{check.status} {check.approval_id or ''} {list(check.stale_fields) or ''}".strip()
            pre.diagnostic("collection evidence matches the exact approved verifier image", True,
                           f"{len(review.collection)} tests, verifier {review.bindings.verifier_image_id}")
        except (ApprovalBlocked, ApprovalError, PolicyViolation, OSError) as exc:
            status = f"unavailable: {plain(exc, 300)}"
    pre.diagnostic("approval state", status.startswith("APPROVED"), status)
    terminal.write("\n".join(["=" * 78, "PACK VALIDATION (read-only; validation never approves a pack)", "=" * 78, "",
                              *_render_pack(pack), "", pre.render()]))
    return exit_codes.OK
