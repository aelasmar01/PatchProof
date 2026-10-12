"""PP-007: pack approval records (PROJECT_SPEC.md 7.5, INV-10).

Only synthetic identifiers are used: `sha256:1111…` verifier images, `example-profile`, and
the reviewer "Synthetic Reviewer". No real PaperTrail approval is created; the verifier
image, final profile and real collection do not exist yet.
"""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
import stat
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from patchproof.core.approvals import (
    ApprovalError,
    ApprovalStore,
    BindingInputs,
    ReviewDecision,
    canonical_sha256,
    check_approval,
    confirmation_phrase,
    create_approval,
    current_approval,
)
from patchproof.core.records import load_record
from patchproof.core.records.pack import ApprovalRecord, CollectedTest, ExecutionProfileV11
from patchproof.packs.collection import review_collection
from patchproof.packs.validation import ValidatedPack, validate_pack

ROOT = Path(__file__).resolve().parents[2]
PACK = ROOT / "examples" / "packs" / "papertrail-document-access"
NOW = datetime(2026, 10, 12, 12, 0, 0, tzinfo=UTC)
SYNTHETIC_IMAGE = "sha256:" + "1" * 64
SYNTHETIC_PROFILE = json.loads((ROOT / "schemas/examples/valid/execution-profile.v1.1--papertrail-reference.json")
                               .read_text())


def inputs_for(pack: ValidatedPack, **overrides: object) -> BindingInputs:
    collection = review_collection(pack.manifest.tests,
                                   [CollectedTest(id=t.id, nodeid=t.nodeid) for t in pack.manifest.tests])
    profile = load_record(ExecutionProfileV11, json.dumps(SYNTHETIC_PROFILE).encode())
    base = BindingInputs(pack_id=pack.manifest.pack_id, pack_version=pack.manifest.pack_version,
                         manifest_sha256=pack.manifest_sha256, pack_tree_sha256=pack.pack_tree_sha256,
                         collection=collection, verifier_image_id=SYNTHETIC_IMAGE, verifier_plugin_version="0.1.0",
                         profile_id="example-profile", profile_sha256=canonical_sha256(profile))
    return dataclasses.replace(base, **overrides)  # type: ignore[arg-type]


def decision(bindings_inputs: BindingInputs, **overrides: str) -> ReviewDecision:
    values = {"asserted_identity": "Synthetic Reviewer", "rationale": "Synthetic unit-test review.",
              "scope": "Unit test only.", "typed_confirmation": confirmation_phrase(bindings_inputs.bindings())}
    values.update(overrides)
    return ReviewDecision(**values)


@pytest.fixture(scope="module")
def pack() -> ValidatedPack:
    return validate_pack(PACK)


@pytest.fixture
def store(tmp_path: Path) -> ApprovalStore:
    root = tmp_path / "approvals"
    root.mkdir(mode=0o700)
    return ApprovalStore(Path(os.path.realpath(root)))


def approve(store: ApprovalStore, inputs: BindingInputs, supersedes: ApprovalRecord | None = None) -> ApprovalRecord:
    record = create_approval(inputs.bindings(), decision(inputs), supersedes=supersedes, now=NOW)
    store.save(record)
    return record


# ------------------------------------------------------------ creation needs an explicit action


def test_approval_binds_every_required_input(pack: ValidatedPack) -> None:
    inputs = inputs_for(pack)
    record = create_approval(inputs.bindings(), decision(inputs), supersedes=None, now=NOW)
    b = record.bindings
    assert (b.pack_id, b.pack_version, b.pack_schema_version) == ("papertrail-document-access", "1.0.0", "1.0")
    assert (b.manifest_sha256, b.pack_tree_sha256) == (pack.manifest_sha256, pack.pack_tree_sha256)
    assert [c.id for c in b.expected_collection] == [t.id for t in pack.manifest.tests]
    assert (b.verifier_image_id, b.verifier_plugin_version, b.profile_id) == (SYNTHETIC_IMAGE, "0.1.0",
                                                                              "example-profile")
    assert record.reviewer.basis == "local-assertion-unverified"
    assert record.created_at == "2026-10-12T12:00:00Z" and record.supersedes is None
    assert record.approval_id.startswith("apr-") and len(record.approval_id) == 36


@pytest.mark.parametrize("typed", ["", "yes", "APPROVE", "approve papertrail-document-access 1.0.0",
                                   "APPROVE papertrail-document-access 1.0.0 000000000000"])
def test_wrong_or_missing_confirmation_approves_nothing(pack: ValidatedPack, typed: str) -> None:
    inputs = inputs_for(pack)
    with pytest.raises(ApprovalError, match="nothing was approved"):
        create_approval(inputs.bindings(), decision(inputs, typed_confirmation=typed), supersedes=None, now=NOW)


def test_confirmation_names_pack_version_and_manifest_hash(pack: ValidatedPack) -> None:
    phrase = confirmation_phrase(inputs_for(pack).bindings())
    assert phrase == f"APPROVE papertrail-document-access 1.0.0 {pack.manifest_sha256[7:19]}"


def test_review_decision_has_no_defaults() -> None:
    assert all(f.default is dataclasses.MISSING and f.default_factory is dataclasses.MISSING
               for f in dataclasses.fields(ReviewDecision))


@pytest.mark.parametrize("field", ["asserted_identity", "rationale", "scope"])
def test_empty_or_control_character_review_text_is_refused(pack: ValidatedPack, field: str) -> None:
    inputs = inputs_for(pack)
    for bad in ("", "\x1b[2Jcleared"):
        with pytest.raises(ValueError):
            create_approval(inputs.bindings(), decision(inputs, **{field: bad}), supersedes=None, now=NOW)


def test_naive_time_is_refused_and_offsets_normalize_to_utc(pack: ValidatedPack) -> None:
    inputs = inputs_for(pack)
    with pytest.raises(ApprovalError):
        create_approval(inputs.bindings(), decision(inputs), supersedes=None, now=datetime(2026, 10, 12))
    local = datetime(2026, 10, 12, 14, 0, tzinfo=timezone(timedelta(hours=2)))
    assert create_approval(inputs.bindings(), decision(inputs), supersedes=None, now=local).created_at == (
        "2026-10-12T12:00:00Z")


# ------------------------------------------------------------ staleness: any changed input


def test_unchanged_inputs_are_approved(pack: ValidatedPack, store: ApprovalStore) -> None:
    record = approve(store, inputs_for(pack))
    result = check_approval(store.records().values(), inputs_for(pack))
    assert (result.status, result.approval_id, result.stale_fields) == ("APPROVED", record.approval_id, ())


def test_no_approval_is_missing(pack: ValidatedPack, store: ApprovalStore) -> None:
    assert check_approval(store.records().values(), inputs_for(pack)).status == "APPROVAL_MISSING"


@pytest.mark.parametrize(("override", "field"), [
    ({"manifest_sha256": "sha256:" + "a" * 64}, "manifest_sha256"),
    ({"pack_tree_sha256": "sha256:" + "b" * 64}, "pack_tree_sha256"),
    ({"pack_version": "1.0.1"}, "pack_version"),
    ({"verifier_image_id": "sha256:" + "2" * 64}, "verifier_image_id"),
    ({"verifier_plugin_version": "0.1.1"}, "verifier_plugin_version"),
    ({"profile_id": "other-profile"}, "profile_id"),
    ({"profile_sha256": "sha256:" + "c" * 64}, "profile_sha256"),
])
def test_changing_any_bound_input_makes_the_approval_stale(pack: ValidatedPack, store: ApprovalStore,
                                                           override: dict[str, str], field: str) -> None:
    approve(store, inputs_for(pack))
    result = check_approval(store.records().values(), inputs_for(pack, **override))
    assert (result.status, result.stale_fields) == ("APPROVAL_STALE", (field,))


def test_changed_collection_is_stale(pack: ValidatedPack, store: ApprovalStore) -> None:
    approve(store, inputs_for(pack))
    reordered = tuple(reversed(inputs_for(pack).collection))
    result = check_approval(store.records().values(), inputs_for(pack, collection=reordered))
    assert (result.status, result.stale_fields) == ("APPROVAL_STALE", ("expected_collection",))


def test_changed_test_content_manifest_or_fixture_is_stale(pack: ValidatedPack, store: ApprovalStore,
                                                           tmp_path: Path) -> None:
    approve(store, inputs_for(pack))
    for change in ("test", "manifest", "readme"):
        root = tmp_path / change
        shutil.copytree(PACK, root)
        if change == "test":
            path = root / "tests" / "test_documents.py"
            path.write_text(path.read_text().replace('FORGED_TOKEN = "pt-synthetic-unknown-a86591090626"',
                                                     'FORGED_TOKEN = "pt-synthetic-unknown-000000000000"'))
        elif change == "manifest":
            path = root / "pack.json"
            path.write_text(path.read_text().replace('"case_timeout_seconds": 20', '"case_timeout_seconds": 21'))
        else:
            (root / "README.md").write_text((root / "README.md").read_text() + "\nEdited.\n")
        changed = validate_pack(Path(os.path.realpath(root)))
        result = check_approval(store.records().values(), inputs_for(changed))
        expected = {"pack_tree_sha256"} | ({"manifest_sha256"} if change == "manifest" else set())
        assert result.status == "APPROVAL_STALE" and set(result.stale_fields) == expected, change


def test_profile_hash_tracks_every_profile_field() -> None:
    base = load_record(ExecutionProfileV11, json.dumps(SYNTHETIC_PROFILE).encode())
    tweaked = {**SYNTHETIC_PROFILE, "timeouts": {**SYNTHETIC_PROFILE["timeouts"], "readiness_seconds": 31}}
    assert canonical_sha256(base) != canonical_sha256(load_record(ExecutionProfileV11, json.dumps(tweaked).encode()))
    reordered = json.dumps(dict(reversed(list(SYNTHETIC_PROFILE.items())))).encode()
    assert canonical_sha256(base) == canonical_sha256(load_record(ExecutionProfileV11, reordered))


# ------------------------------------------------------------ supersession and history


def test_replacement_supersedes_and_preserves_history(pack: ValidatedPack, store: ApprovalStore) -> None:
    first = approve(store, inputs_for(pack))
    newer_inputs = inputs_for(pack, verifier_image_id="sha256:" + "3" * 64)
    assert check_approval(store.records().values(), newer_inputs).status == "APPROVAL_STALE"
    second = approve(store, newer_inputs, supersedes=first)
    assert second.supersedes == first.approval_id
    assert set(store.records()) == {first.approval_id, second.approval_id}
    assert store.current(pack.manifest.pack_id) == second
    assert check_approval(store.records().values(), newer_inputs).status == "APPROVED"
    stale = check_approval(store.records().values(), inputs_for(pack), approval_id=first.approval_id)
    assert (stale.status, stale.stale_fields) == ("APPROVAL_STALE", ("superseded",))


def test_history_forks_and_dangling_links_are_refused(pack: ValidatedPack, store: ApprovalStore) -> None:
    first = approve(store, inputs_for(pack))
    approve(store, inputs_for(pack), supersedes=first)
    with pytest.raises(ApprovalError, match="already been superseded"):
        approve(store, inputs_for(pack), supersedes=first)
    fork = create_approval(inputs_for(pack).bindings(), decision(inputs_for(pack)), supersedes=first, now=NOW)
    with pytest.raises(ApprovalError, match="superseded twice"):
        current_approval([*store.records().values(), fork], pack.manifest.pack_id)
    orphan = create_approval(inputs_for(pack).bindings(), decision(inputs_for(pack)), supersedes=None, now=NOW)
    dangling = orphan.model_copy(update={"supersedes": "apr-" + "f" * 32})
    with pytest.raises(ApprovalError, match="missing"):
        current_approval([dangling], pack.manifest.pack_id)
    with pytest.raises(ApprovalError, match="more than one current"):
        current_approval([first, orphan], pack.manifest.pack_id)


def test_cannot_supersede_another_packs_approval(pack: ValidatedPack, store: ApprovalStore) -> None:
    first = approve(store, inputs_for(pack))
    other = inputs_for(pack, pack_id="other-pack")
    with pytest.raises(ApprovalError, match="same pack"):
        create_approval(other.bindings(), decision(other), supersedes=first, now=NOW)


# ------------------------------------------------------------ the store is append-only


def test_records_are_written_once_read_only_and_never_overwritten(pack: ValidatedPack, store: ApprovalStore) -> None:
    record = approve(store, inputs_for(pack))
    path = store.root / f"{record.approval_id}.json"
    assert stat.S_IMODE(os.lstat(path).st_mode) == 0o400
    with pytest.raises(FileExistsError):
        store.save(record)
    assert load_record(ApprovalRecord, path.read_bytes()) == record


def test_store_refuses_tampered_or_foreign_entries(pack: ValidatedPack, store: ApprovalStore) -> None:
    record = approve(store, inputs_for(pack))
    path = store.root / f"{record.approval_id}.json"
    os.chmod(path, 0o600)
    data = json.loads(path.read_text())
    data["reviewer"]["basis"] = "verified-human"
    path.write_text(json.dumps(data))
    with pytest.raises(ApprovalError, match="not a valid approval record"):
        store.records()
    path.write_text(json.dumps({**json.loads(path.read_text()), "reviewer": record.reviewer.model_dump()}))
    (store.root / "notes.txt").write_text("x")
    with pytest.raises(ApprovalError, match="unexpected entry"):
        store.records()


def test_fifo_in_the_store_is_refused(pack: ValidatedPack, store: ApprovalStore) -> None:
    os.mkfifo(store.root / f"apr-{'d' * 32}.json")
    with pytest.raises(ApprovalError, match="unexpected entry"):
        store.records()


def test_renamed_record_is_refused(pack: ValidatedPack, store: ApprovalStore) -> None:
    record = approve(store, inputs_for(pack))
    os.rename(store.root / f"{record.approval_id}.json", store.root / f"apr-{'e' * 32}.json")
    with pytest.raises(ApprovalError, match="does not match"):
        store.records()


def test_store_root_swapped_for_a_symlink_is_refused(pack: ValidatedPack, store: ApprovalStore,
                                                     tmp_path: Path) -> None:
    approve(store, inputs_for(pack))
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    os.rename(store.root, tmp_path / "moved")
    store.root.symlink_to(elsewhere)
    with pytest.raises(ApprovalError, match="symlink"):
        store.records()
    with pytest.raises(ApprovalError, match="symlink"):
        approve(store, inputs_for(pack))
    assert list(elsewhere.iterdir()) == []


def test_store_root_replaced_by_another_directory_is_refused(pack: ValidatedPack, store: ApprovalStore,
                                                             tmp_path: Path) -> None:
    approve(store, inputs_for(pack))
    os.rename(store.root, tmp_path / "moved")
    store.root.mkdir(mode=0o700)
    with pytest.raises(ApprovalError, match="same private"):
        store.records()
    with pytest.raises(ApprovalError, match="same private"):
        approve(store, inputs_for(pack))
    assert list(store.root.iterdir()) == []


def test_store_whose_mode_is_loosened_later_is_refused(pack: ValidatedPack, store: ApprovalStore) -> None:
    os.chmod(store.root, 0o755)
    with pytest.raises(ApprovalError, match="same private"):
        store.records()


def test_store_must_be_private_canonical_and_owned(tmp_path: Path) -> None:
    open_dir = tmp_path / "open"
    open_dir.mkdir(mode=0o755)
    os.chmod(open_dir, 0o755)
    with pytest.raises(ApprovalError, match="private"):
        ApprovalStore(Path(os.path.realpath(open_dir)))
    with pytest.raises(ApprovalError, match="canonical"):
        ApprovalStore(Path("relative"))


def test_no_papertrail_approval_exists_in_the_repository() -> None:
    hits = [p for p in ROOT.rglob("apr-*.json") if ".venv" not in p.parts]
    assert hits == []
