"""PP-007: pack validation (static, fail closed) and the exact-collection contract.

Every negative case copies the reviewed PaperTrail pack into a temporary directory and breaks
exactly one thing. Validation reads bytes and parses with `ast`; no pack module is imported,
which a test asserts.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from patchproof.core.records.pack import CollectedTest
from patchproof.packs.collection import (
    COLLECTION_OUTPUT_CAP,
    FORBIDDEN_ENV,
    CollectionMismatch,
    check_run_collection,
    collection_plan,
    parse_collected,
    review_collection,
)
from patchproof.packs.validation import FIXTURE_CONTRACTS, PackError, ValidatedPack, pack_tree_sha256, validate_pack

ROOT = Path(__file__).resolve().parents[2]
PACK = ROOT / "examples" / "packs" / "papertrail-document-access"
TEST_MODULE = "tests/test_documents.py"
GROUND_TRUTH = json.loads((ROOT / "examples" / "papertrail" / "reference-fixture.json").read_text())


def copy_pack(tmp_path: Path) -> Path:
    dest = tmp_path / "pack"
    shutil.copytree(PACK, dest)
    return Path(os.path.realpath(dest))


def edit(path: Path, old: str, new: str) -> None:
    text = path.read_text()
    assert text.count(old) >= 1, old
    path.write_text(text.replace(old, new, 1))


def manifest_edit(root: Path, change: Callable[[dict], None]) -> None:  # type: ignore[type-arg]
    data = json.loads((root / "pack.json").read_text())
    change(data)
    (root / "pack.json").write_text(json.dumps(data, indent=2))


@pytest.fixture(scope="module")
def pack() -> ValidatedPack:
    return validate_pack(PACK)


# ------------------------------------------------------------ the reviewed pack


def test_papertrail_pack_is_valid_and_covers_the_eight_checks(pack: ValidatedPack) -> None:
    tests = {t.id: t for t in pack.manifest.tests}
    assert sorted(tests) == ["AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004", "FUNC-001", "FUNC-002", "FUNC-003",
                             "FUNC-004"]
    declared = {c["id"]: c for c in GROUND_TRUTH["checks"]}
    for test_id, test in tests.items():
        assert test.kind == declared[test_id]["kind"]
        assert test.baseline_expected == declared[test_id]["expected"]["vulnerable"]["semantic"]
        assert test.candidate_expected == ("SECURE" if test.kind == "security" else "PASS")
    assert pack.manifest.fixture_contract == GROUND_TRUTH["target"]["fixture_contract"]
    assert [f.path for f in pack.files] == ["README.md", "fixtures/synthetic-documents-v1.json", "pack.json",
                                            TEST_MODULE]


def test_fixture_contract_registry_matches_pp006(pack: ValidatedPack) -> None:
    assert FIXTURE_CONTRACTS["synthetic-documents-v1"] == GROUND_TRUTH["target"]["fixture_sha256"]


def test_validation_never_imports_pack_code(pack: ValidatedPack) -> None:
    assert not any(m == "test_documents" or m.endswith(".test_documents") for m in sys.modules)


def test_hashes_are_deterministic_and_content_bound(tmp_path: Path, pack: ValidatedPack) -> None:
    again = validate_pack(copy_pack(tmp_path))
    assert (again.manifest_sha256, again.pack_tree_sha256) == (pack.manifest_sha256, pack.pack_tree_sha256)
    assert pack.pack_tree_sha256 == pack_tree_sha256(tuple(reversed(pack.files)))
    edit(tmp_path / "pack" / "README.md", "synthetic", "Synthetic")
    changed = validate_pack(Path(os.path.realpath(tmp_path / "pack")))
    assert changed.manifest_sha256 == pack.manifest_sha256 and changed.pack_tree_sha256 != pack.pack_tree_sha256


# ------------------------------------------------------------ manifest rules


def _rejected(root: Path, code: str, match: str | None = None) -> None:
    with pytest.raises(PackError, match=match) as caught:
        validate_pack(root)
    assert caught.value.code == code


@pytest.mark.parametrize(("change", "match"), [
    (lambda d: d.update(schema_version="2.0"), "schema_version"),
    (lambda d: d.update(unknown_field=1), "Extra inputs"),
    (lambda d: d.update(title="{{ PACK_TITLE }}"), "placeholder"),
    (lambda d: d.update(expectation="Readable only by ${OWNER}."), "placeholder"),
    (lambda d: d.update(title="TODO describe this pack"), "placeholder"),
    (lambda d: d["tests"].append(dict(d["tests"][0], nodeid="tests/test_documents.py::test_other")),
     "duplicate test ID"),
    (lambda d: d["tests"].append(dict(d["tests"][0], id="AUTH-099")), "duplicate pytest node ID"),
    (lambda d: d.update(tests=[t for t in d["tests"] if t["kind"] == "security"]), "INV-08"),
    (lambda d: d.update(tests=[t if t["id"] != "AUTH-001" else dict(t, baseline_expected="SECURE")
                               for t in d["tests"] if t["id"] != "AUTH-003"]), "INV-06"),
    (lambda d: d["tests"][0].update(candidate_expected="PASS"), "SECURE on the candidate"),
    (lambda d: d["tests"][4].update(baseline_expected="SECURE"), "PASS on both"),
    (lambda d: d["tests"][0].update(nodeid="/etc/tests/test_x.py::test_y"), "tests/0/nodeid"),
    (lambda d: d["tests"][0].update(nodeid="tests/../test_x.py::test_y"), "tests/0/nodeid"),
    (lambda d: d["tests"][0].update(nodeid="tests/test_documents.py::test_x[--pdb]"), "parametrized"),
    (lambda d: d.update(fixture_contract="unknown-contract"), "unknown fixture contract"),
])
def test_manifest_rules(tmp_path: Path, change: Callable[[dict], None], match: str) -> None:  # type: ignore[type-arg]
    root = copy_pack(tmp_path)
    manifest_edit(root, change)
    with pytest.raises(PackError, match=match) as caught:
        validate_pack(root)
    assert caught.value.code in ("PACK_MANIFEST_INVALID", "PACK_FIXTURE_INVALID")


@pytest.mark.parametrize("raw", [
    b'{"schema_version": "1.0", "schema_version": "1.0"}',
    b'{"pairs": NaN}',
    b"\xef\xbb\xbf{}",
    b"[" * 40 + b"]" * 40,
])
def test_manifest_must_load_strictly(tmp_path: Path, raw: bytes) -> None:
    root = copy_pack(tmp_path)
    (root / "pack.json").write_bytes(raw)
    _rejected(root, "PACK_MANIFEST_INVALID")


def test_oversized_manifest(tmp_path: Path) -> None:
    root = copy_pack(tmp_path)
    (root / "pack.json").write_bytes(b" " * 70000 + (PACK / "pack.json").read_bytes())
    _rejected(root, "PACK_TOO_LARGE")


# ------------------------------------------------------------ layout and paths


@pytest.mark.parametrize(("make", "code"), [
    (lambda r: (r / "tests" / "conftest.py").write_text("x = 1\n"), "PACK_PATH_INVALID"),
    (lambda r: (r / "conftest.py").write_text("x = 1\n"), "PACK_PATH_INVALID"),
    (lambda r: (r / "pytest.ini").write_text("[pytest]\n"), "PACK_PATH_INVALID"),
    (lambda r: (r / "pyproject.toml").write_text(""), "PACK_PATH_INVALID"),
    (lambda r: (r / "tests" / "__init__.py").write_text(""), "PACK_PATH_INVALID"),
    (lambda r: (r / ".hidden").write_text(""), "PACK_PATH_INVALID"),
    (lambda r: (r / "tests" / "__pycache__").mkdir(), "PACK_PATH_INVALID"),
    (lambda r: (r / "tests" / "helper.py").write_text(""), "PACK_PATH_INVALID"),
    (lambda r: (r / "scripts").mkdir(), "PACK_PATH_INVALID"),
    (lambda r: (r / "fixtures" / "extra.json").write_text("{}"), "PACK_FIXTURE_INVALID"),
    (lambda r: (r / "tests" / "test_unreferenced.py").write_text(""), "PACK_TEST_INVALID"),
    (lambda r: (r / "tests" / "link.py").symlink_to("/etc/hosts"), "PACK_PATH_INVALID"),
    (lambda r: (r / "fixtures" / "synthetic-documents-v1.json").unlink(), "PACK_FIXTURE_INVALID"),
    (lambda r: (r / "README.md").unlink(), "PACK_INCOMPLETE"),
    (lambda r: (r / "README.md").write_text("  \n"), "PACK_INCOMPLETE"),
    (lambda r: (r / TEST_MODULE).unlink(), "PACK_TEST_INVALID"),
    (lambda r: os.mkfifo(r / "fixtures" / "fifo.json"), "PACK_PATH_INVALID"),
    (lambda r: (r / "fixtures" / "big.json").write_bytes(b" " * 262145), "PACK_TOO_LARGE"),
])
def test_layout_rules(tmp_path: Path, make: Callable[[Path], object], code: str) -> None:
    root = copy_pack(tmp_path)
    make(root)
    _rejected(root, code)


def test_file_swapped_for_a_fifo_after_lstat_is_refused_without_blocking(tmp_path: Path,
                                                                        monkeypatch: pytest.MonkeyPatch) -> None:
    """Race: lstat sees a regular file, but a FIFO is opened. Must refuse promptly, not hang."""
    import threading

    from patchproof.packs import validation

    root = copy_pack(tmp_path)
    fifo = root / "fixtures" / "late.json"
    os.mkfifo(fifo)
    regular = os.lstat(root / "README.md")
    real_lstat = os.lstat

    def lying_lstat(path: object, *args: object, **kwargs: object) -> os.stat_result:
        return regular if str(path) == str(fifo) else real_lstat(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(validation.os, "lstat", lying_lstat)
    outcome: list[BaseException | None] = []

    def run() -> None:
        try:
            validate_pack(root)
            outcome.append(None)
        except BaseException as exc:  # noqa: BLE001 - recorded for the assertion below
            outcome.append(exc)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout=10)
    assert not worker.is_alive(), "validation blocked on a FIFO"
    assert isinstance(outcome[0], PackError) and outcome[0].code == "PACK_PATH_INVALID"


def test_file_swapped_for_another_same_size_file_after_lstat_is_refused(tmp_path: Path,
                                                                      monkeypatch: pytest.MonkeyPatch) -> None:
    """Race: lstat describes one regular file, a different one of the same size is opened."""
    from patchproof.packs import validation

    root = copy_pack(tmp_path)
    readme = root / "README.md"
    decoy = tmp_path / "decoy.md"
    decoy.write_bytes(b"x" * readme.stat().st_size)
    decoy_stat = os.lstat(decoy)
    real_lstat = os.lstat

    def lying_lstat(path: object, *args: object, **kwargs: object) -> os.stat_result:
        return decoy_stat if str(path) == str(readme) else real_lstat(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(validation.os, "lstat", lying_lstat)
    with pytest.raises(PackError, match="changed type or identity") as caught:
        validate_pack(root)
    assert caught.value.code == "PACK_PATH_INVALID"


def test_symlinked_fixture_is_refused(tmp_path: Path) -> None:
    root = copy_pack(tmp_path)
    fixture = root / "fixtures" / "synthetic-documents-v1.json"
    real = tmp_path / "real.json"
    shutil.copy(fixture, real)
    fixture.unlink()
    fixture.symlink_to(real)
    _rejected(root, "PACK_PATH_INVALID")


def test_changed_fixture_copy_is_refused(tmp_path: Path) -> None:
    root = copy_pack(tmp_path)
    edit(root / "fixtures" / "synthetic-documents-v1.json", '"reader_roles": []', '"reader_roles": ["auditor"]')
    _rejected(root, "PACK_FIXTURE_INVALID", "differs from the reviewed contract")


def test_root_must_be_canonical(tmp_path: Path) -> None:
    root = copy_pack(tmp_path)
    (tmp_path / "alias").symlink_to(root)
    _rejected(tmp_path / "alias", "PACK_PATH_INVALID")
    _rejected(Path("relative/pack"), "PACK_PATH_INVALID")


# ------------------------------------------------------------ static checks of test modules


@pytest.mark.parametrize(("old", "new", "match"), [
    ("from __future__ import annotations\n", "from __future__ import annotations\nimport os\n", "imports"),
    ("from __future__ import annotations\n", "from __future__ import annotations\nimport pytest\n", "imports"),
    ("from __future__ import annotations\n", "from __future__ import annotations\nfrom papertrail import app\n",
     "imports"),
    ("from __future__ import annotations\n", "from __future__ import annotations\nfrom . import x\n", "relative"),
    ("def test_owner_reads_own_document(", "@skip\ndef test_owner_reads_own_document(", "decorators"),
    ("    caller = documents.user(\"u-alice\")\n    document = documents.document(\"doc-alice-private\")\n"
     "    response = target.get(f\"/documents/{document.document_id}\", bearer=caller.token)\n"
     "    expect_document_read(",
     "    pytest.skip(\"later\")\n    caller = documents.user(\"u-alice\")\n"
     "    document = documents.document(\"doc-alice-private\")\n"
     "    response = target.get(f\"/documents/{document.document_id}\", bearer=caller.token)\n"
     "    expect_document_read(", "pytest.skip"),
    ("    assess_unauthorized_read(check, caller=caller, document=document, response=response)\n\n\n"
     "def test_unauthenticated",
     "    try:\n        assess_unauthorized_read(check, caller=caller, document=document, response=response)\n"
     "    except BaseException:\n        pass\n\n\ndef test_unauthenticated", "try/with"),
    ("    assess_unauthorized_read(check, caller=caller, document=document, response=response)\n\n\n"
     "def test_unauthenticated",
     "    assess_unauthorized_read(check, caller=caller, document=document, response=response)\n"
     "    check.secure(None)\n\n\ndef test_unauthenticated", "exactly one terminal"),
    ("def test_owner_reads_own_document(documents",
     "def test_owner_reads_own_document(check: SecurityCheck, documents", "must not use the security helpers"),
    ("def test_nonowner_cannot_read_private_document(check: SecurityCheck, documents",
     "def test_nonowner_cannot_read_private_document(documents", "check fixture"),
    ("    expect_identity(caller=caller, response=response)\n", "    response.status\n", "no legitimate-behavior"),
    ("def test_caller_reads_own_identity(", "def test_extra_unlisted() -> None:\n    assert True\n\n\n"
                                           "def test_caller_reads_own_identity(", "differ from the manifest"),
    ("def test_caller_reads_own_identity(", "def test_caller_reads_own_identity_renamed(", "differ from the manifest"),
    ("    response = target.get(\"/me\"", "    response = target._client.get(\"/me\"", "construct"),
    ("FORGED_TOKEN = ", "eval('1')\nFORGED_TOKEN = ", "eval"),
    ("def test_owner_reads_own_document(", "async def test_owner_reads_own_document(", "async"),
])
def test_static_module_rules(tmp_path: Path, old: str, new: str, match: str) -> None:
    root = copy_pack(tmp_path)
    edit(root / TEST_MODULE, old, new)
    with pytest.raises(PackError, match=match):
        validate_pack(root)


def test_unparseable_module(tmp_path: Path) -> None:
    root = copy_pack(tmp_path)
    (root / TEST_MODULE).write_bytes(b"def broken(:\n")
    _rejected(root, "PACK_TEST_INVALID")


# ------------------------------------------------------------ collection plan and validation


def test_collection_plan_is_explicit_and_isolated(pack: ValidatedPack) -> None:
    plan = collection_plan(pack)
    env = dict(plan.env)
    assert env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert not FORBIDDEN_ENV & set(env)
    assert set(env) == {"PATH", "LC_ALL", "HOME", "PYTEST_DISABLE_PLUGIN_AUTOLOAD", "PYTHONDONTWRITEBYTECODE",
                        "PYTHONHASHSEED"}
    # PP-008: collection starts through the PatchProof launcher, which opens the event channel
    # before pytest starts and runs pytest with -c /opt/patchproof/verifier/pytest.ini.
    assert list(plan.argv) == ["/usr/local/bin/python3", "-I", "-B", "-m", "patchproof_verifier.launch", "collect",
                               "--pack", "/pack", "--", "/pack/tests/test_documents.py"]
    assert plan.timeout_seconds == 30 and plan.output_cap_bytes == COLLECTION_OUTPUT_CAP


def test_owned_pytest_configuration_disables_discovery_paths() -> None:
    ini = (ROOT / "verifier" / "pytest.ini").read_text()
    for option in ("-p patchproof_verifier.plugin", "--noconftest", "--strict-markers", "--strict-config",
                   "-p no:cacheprovider", "xfail_strict = true"):
        assert option in ini


def collected(pack: ValidatedPack, order: list[int] | None = None) -> list[CollectedTest]:
    tests = [CollectedTest(id=t.id, nodeid=t.nodeid) for t in pack.manifest.tests]
    return [tests[i] for i in order] if order else tests


def test_review_collection_accepts_exactly_the_manifest(pack: ValidatedPack) -> None:
    order = [7, 6, 5, 4, 3, 2, 1, 0]
    got = review_collection(pack.manifest.tests, collected(pack, order))
    assert [c.id for c in got] == [pack.manifest.tests[i].id for i in order]


@pytest.mark.parametrize("change", [
    lambda c: c[:-1],
    lambda c: [*c, CollectedTest(id="AUTH-099", nodeid="tests/test_documents.py::test_extra")],
    lambda c: [*c, c[0]],
    lambda c: [CollectedTest(id="AUTH-002", nodeid=c[0].nodeid), *c[1:]],
])
def test_review_collection_rejects_missing_extra_duplicate_or_renamed(pack: ValidatedPack,
                                                                      change: Callable[[list[CollectedTest]],
                                                                                       list[CollectedTest]]) -> None:
    with pytest.raises(CollectionMismatch):
        review_collection(pack.manifest.tests, change(collected(pack)))


def test_run_collection_must_equal_the_approved_order(pack: ValidatedPack) -> None:
    approved = collected(pack)
    check_run_collection(approved, list(approved))
    with pytest.raises(CollectionMismatch):
        check_run_collection(approved, approved[::-1])
    with pytest.raises(CollectionMismatch):
        check_run_collection(approved, approved[:-1])


def test_collected_record_is_parsed_strictly(pack: ValidatedPack) -> None:
    good = json.dumps({"tests": [c.model_dump() for c in collected(pack)]}).encode()
    assert len(parse_collected(good)) == 8
    for bad in (b'{"tests": [], "tests": []}', b'{"tests": [{"id": "AUTH-001"}]}',
                b'{"tests": [{"id": "AUTH-001", "nodeid": "../x.py::test_y"}]}', b'{"tests": "all"}',
                b"PASS", b" " * (COLLECTION_OUTPUT_CAP + 1)):
        with pytest.raises(CollectionMismatch):
            parse_collected(bad)
