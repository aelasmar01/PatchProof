"""PP-008: run-authorization records, semantic checks and the private store, Docker-free.

Records here are built from the schema example (`run-authorization--papertrail-r1-r3-example`),
which is labeled as an example and authorizes nothing. Every store is a temporary directory.
"""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from patchproof.core.records import RecordError, load_record, validate_record
from patchproof.core.records.authorization import RunAuthorization, RunPlanDocument
from patchproof.core.run_authorizations import (
    AuthorizationDecision,
    RunAuthorizationError,
    RunAuthorizationStore,
    authorization_phrase,
    check_authorization,
    container_names,
    create_authorization,
    plan_sha256,
)

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = json.loads((ROOT / "schemas/examples/valid/run-authorization--papertrail-r1-r3-example.json").read_text())
NOW = datetime(2026, 10, 13, 12, 0, tzinfo=UTC)


def plan_for(run_id: str) -> RunPlanDocument:
    doc = copy.deepcopy(EXAMPLE["plan"])
    doc["run_id"] = run_id
    doc["containers"]["sequence"] = [{"side": s, "role": r, "name": n} for s, r, n in container_names(run_id)]
    doc["evidence"]["destination"] = f"evidence/runs/{run_id}"
    return validate_record(RunPlanDocument, doc)


def record_for(run_id: str, supersedes: RunAuthorization | None = None) -> RunAuthorization:
    plan = plan_for(run_id)
    return create_authorization(plan, AuthorizationDecision("Synthetic Owner", "Synthetic rationale.",
                                                            "Synthetic scope.", authorization_phrase(plan)),
                                supersedes=supersedes, now=NOW)


def run_id(n: int) -> str:
    return "run-" + format(n, "x").rjust(4, "a") + "0123456789abcdef0123456789ab"


@pytest.fixture
def store(tmp_path: Path) -> RunAuthorizationStore:
    root = tmp_path / "run-authorizations"
    os.mkdir(root, 0o700)
    return RunAuthorizationStore(Path(os.path.realpath(root)))


# ------------------------------------------------------------------ records


def test_the_example_is_valid_and_hash_consistent() -> None:
    record = load_record(RunAuthorization, json.dumps(EXAMPLE).encode(), contract="run-authorization")
    check_authorization(record)
    assert record.plan_sha256 == plan_sha256(record.plan)
    assert record.plan.repetitions.pairs == 1 and record.plan.fixture.seed is None


@pytest.mark.parametrize(("path", "value", "message"), [
    (("plan_sha256",), "sha256:" + "12" * 32, "not the hash of the plan"),
    (("plan", "images", "target_image_id"), "sha256:" + "0" * 64, "placeholder"),
    (("plan", "containers", "sequence", 0, "name"), "pp-run-0123456789ab-p1-candidate-target", "container sequence"),
    (("plan", "evidence", "destination"), "evidence/runs/run-" + "fe" * 16, "evidence destination"),
    (("plan", "source_inclusion", "include"), ["papertrail", "fixtures/synthetic"], "sorted"),
])
def test_semantic_rules_the_schema_cannot_express(path: tuple[Any, ...], value: Any, message: str) -> None:
    doc = copy.deepcopy(EXAMPLE)
    target = doc
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    if path[0] == "plan":
        doc["plan_sha256"] = plan_sha256(validate_record(RunPlanDocument, doc["plan"]))
    record = load_record(RunAuthorization, json.dumps(doc).encode())
    with pytest.raises(RunAuthorizationError, match=message):
        check_authorization(record)


def test_strict_loading_refuses_duplicate_keys_and_unknown_fields() -> None:
    raw = json.dumps(EXAMPLE)
    with pytest.raises(RecordError):
        load_record(RunAuthorization, raw.replace('"single_use": true', '"single_use": true, "single_use": true', 1)
                    .encode())
    with pytest.raises(RecordError):
        load_record(RunAuthorization, json.dumps({**EXAMPLE, "approved": True}).encode())
    with pytest.raises(RecordError):
        load_record(RunAuthorization, json.dumps({**EXAMPLE, "single_use": 1}).encode())


def test_creation_requires_the_exact_phrase_and_an_aware_time() -> None:
    plan = plan_for(run_id(1))
    with pytest.raises(RunAuthorizationError, match="does not match"):
        create_authorization(plan, AuthorizationDecision("A", "B", "C", f"AUTHORIZE {plan.run_id}"),
                             supersedes=None, now=NOW)
    with pytest.raises(RunAuthorizationError, match="timezone"):
        create_authorization(plan, AuthorizationDecision("A", "B", "C", authorization_phrase(plan)),
                             supersedes=None, now=datetime(2026, 10, 13))
    assert authorization_phrase(plan) == f"AUTHORIZE {plan.run_id} {plan_sha256(plan)}"


# ------------------------------------------------------------------ store


def test_save_scan_and_claim(store: RunAuthorizationStore) -> None:
    first = record_for(run_id(1))
    path = store.save(first)
    assert oct(os.lstat(path).st_mode & 0o777) == "0o400"
    current = store.executable()
    assert current is not None and current.record == first
    claim = store.claim(first.authorization_id, run_id=first.plan.run_id, now=NOW)
    assert json.loads(claim)["run_id"] == first.plan.run_id
    assert oct(os.lstat(store.root / f"{first.authorization_id}.claim").st_mode & 0o777) == "0o400"
    assert store.executable() is None
    with pytest.raises(RunAuthorizationError, match="already been claimed"):
        store.claim(first.authorization_id, run_id=first.plan.run_id, now=NOW)


def test_supersession_rules(store: RunAuthorizationStore) -> None:
    first = record_for(run_id(1))
    store.save(first)
    with pytest.raises(RunAuthorizationError, match="supersede exactly the current unused"):
        store.save(record_for(run_id(2)))
    second = record_for(run_id(2), supersedes=first)
    store.save(second)
    current = store.executable()
    assert current is not None and current.record == second
    with pytest.raises(RunAuthorizationError, match="never reused"):
        store.save(record_for(run_id(1), supersedes=second))
    store.claim(second.authorization_id, run_id=second.plan.run_id, now=NOW)
    with pytest.raises(RunAuthorizationError, match="no unused authorization to supersede"):
        store.save(record_for(run_id(3), supersedes=second))  # a claimed authorization is never superseded
    store.save(record_for(run_id(3)))  # a fresh authorization after the consumed one


@pytest.mark.parametrize("damage", ["unexpected", "tampered", "renamed", "orphan-claim", "symlink"])
def test_a_damaged_store_is_refused(store: RunAuthorizationStore, damage: str) -> None:
    first = record_for(run_id(1))
    path = store.save(first)
    if damage == "unexpected":
        (store.root / "notes.txt").write_text("x")
    elif damage == "tampered":
        os.chmod(path, 0o600)
        doc = json.loads(path.read_text())
        doc["plan"]["runtime"]["result_cap_bytes"] = 65536
        path.write_text(json.dumps(doc))
    elif damage == "renamed":
        os.rename(path, store.root / ("rau-" + "ab" * 16 + ".json"))
    elif damage == "orphan-claim":
        (store.root / ("rau-" + "cd" * 16 + ".claim")).write_text("{}")
    else:
        os.symlink(path, store.root / ("rau-" + "ef" * 16 + ".json"))
    with pytest.raises(RunAuthorizationError):
        store.scan()
    with pytest.raises(RunAuthorizationError):
        store.executable()


def test_the_store_must_be_a_private_directory(tmp_path: Path) -> None:
    loose = tmp_path / "loose"
    os.mkdir(loose, 0o755)
    with pytest.raises(RunAuthorizationError, match="0700"):
        RunAuthorizationStore(Path(os.path.realpath(loose)))
    real = tmp_path / "real"
    os.mkdir(real, 0o700)
    os.symlink(real, tmp_path / "link")
    with pytest.raises(RunAuthorizationError, match="canonical"):
        RunAuthorizationStore(tmp_path / "link")


def test_a_replaced_store_directory_is_refused(store: RunAuthorizationStore, tmp_path: Path) -> None:
    os.rename(store.root, tmp_path / "moved")
    os.mkdir(store.root, 0o700)
    with pytest.raises(RunAuthorizationError, match="same 0700 directory"):
        store.scan()


# ------------------------------------------------------------------ the entry points are interactive only


@pytest.mark.parametrize("module", ["patchproof.run_authorization", "patchproof.run_papertrail_once",
                                    "patchproof.recover_run"])
@pytest.mark.parametrize(("args", "env", "stdin", "message"), [
    ((), None, b"Me\nWhy\nScope\nAUTHORIZE run-x sha256:x\nEXECUTE run-x\n", "interactive terminal"),
    (("--confirm", "EXECUTE run-x"), None, b"", "takes no arguments"),
    ((), {"PATCHPROOF_CONFIRM": "yes"}, b"", "environment variables are not accepted"),
])
def test_noninteractive_invocation_is_refused(tmp_path: Path, module: str, args: tuple[str, ...],
                                              env: dict[str, str] | None, stdin: bytes, message: str) -> None:
    home = tmp_path / "home"
    os.mkdir(home, 0o700)
    result = subprocess.run([sys.executable, "-I", "-m", module, *args], input=stdin,
                            env={"PATH": "/usr/bin:/bin", "HOME": str(home), "LC_ALL": "C.UTF-8", **(env or {})},
                            capture_output=True, timeout=60, cwd=ROOT, check=False)
    assert result.returncode == 2
    assert message in result.stderr.decode() and "NOT " in result.stderr.decode()
    assert list(home.rglob("*")) == []  # nothing created, no store, no evidence


@pytest.mark.parametrize(("module", "expected"), [
    ("patchproof.run_authorization",
     b"NOT AUTHORIZED: pack approval bindings: collection evidence directory is missing"),
    ("patchproof.run_papertrail_once", b"NOT EXECUTED: run-authorization store:"),
    ("patchproof.recover_run", b"NOT RECOVERED: run-authorization store:"),
])
def test_a_foreground_terminal_reaches_the_flow_and_fails_closed(tmp_path: Path, module: str,
                                                                 expected: bytes) -> None:
    import pty

    home = tmp_path / "home"
    os.mkdir(home, 0o700)
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(ROOT)
        os.execve(sys.executable, [sys.executable, "-I", "-m", module],
                  {"PATH": "/usr/bin:/bin", "HOME": str(home), "LC_ALL": "C.UTF-8"})
    out = b""
    while True:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
    _, status = os.waitpid(pid, 0)
    os.close(fd)
    assert os.waitstatus_to_exitcode(status) == 2
    assert expected in out
    assert not any(p.name in ("run-authorizations", "runs") for p in home.rglob("*"))


# ------------------------------------------------------------------ revision identity: contract versus driver


def _with_sources(**sides: dict[str, Any]) -> RunAuthorization:
    doc = copy.deepcopy(EXAMPLE)
    for side, values in sides.items():
        doc["plan"]["sources"][side].update(values)
    doc["plan_sha256"] = plan_sha256(validate_record(RunPlanDocument, doc["plan"]))
    return load_record(RunAuthorization, json.dumps(doc).encode())


def test_the_reusable_contract_allows_a_revision_against_itself() -> None:
    """PROJECT_SPEC.md 17.2 compares the unchanged vulnerable revision against itself."""
    same = _with_sources(candidate=EXAMPLE["plan"]["sources"]["baseline"])
    assert same.plan.sources.baseline == same.plan.sources.candidate
    check_authorization(same)
    plan = same.plan
    created = create_authorization(plan, AuthorizationDecision("Synthetic Owner", "R", "S", authorization_phrase(plan)),
                                   supersedes=None, now=NOW)
    assert created.plan.sources.candidate.commit_id == created.plan.sources.baseline.commit_id


def test_only_the_first_run_driver_pins_r1_against_r3() -> None:
    from patchproof.runner.papertrail_plan import PAPERTRAIL_REVISIONS, PlanError, check_first_run_scope

    example = load_record(RunAuthorization, json.dumps(EXAMPLE).encode())
    check_first_run_scope(example.plan)  # exactly r1 versus r3
    assert PAPERTRAIL_REVISIONS["baseline"].commit_id == "68b2bc0e41cb7e9a074b09f2d97db3e2d2ca288a"
    assert PAPERTRAIL_REVISIONS["candidate"].commit_id == "2fb6d09378906f1df69ac32b862df4a350e8a56d"
    base, cand = EXAMPLE["plan"]["sources"]["baseline"], EXAMPLE["plan"]["sources"]["candidate"]
    for variant, side in [(_with_sources(candidate=base), "candidate"),
                          (_with_sources(baseline=cand, candidate=base), "baseline"),
                          (_with_sources(candidate={"tree_id": base["tree_id"]}), "candidate"),
                          (_with_sources(baseline={"tag": "refs/tags/authz-r2-inadequate"}), "baseline")]:
        check_authorization(variant)  # valid for the reusable contract ...
        with pytest.raises(PlanError, match=f"{side} is not the authorized first-run revision") as caught:
            check_first_run_scope(variant.plan)  # ... but never executable by this driver
        assert (caught.value.precondition, caught.value.code) == ("source_identity", "SOURCE_IDENTITY_MISMATCH")
