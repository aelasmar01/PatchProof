"""PP-008: owner-operated supersession of the current pack approval, Docker-free.

Every record here is SYNTHETIC: it approves the renamed copy of the PaperTrail pack
(`synthetic-approval-test`) in a temporary store. The real approval store is never opened,
and no PaperTrail approval or replacement is created.
"""

from __future__ import annotations

import hashlib
import json
import os
import pty
import subprocess
import sys
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from test_pack_approval import ROOT, Synthetic, FakeTerminal, _private, answers, build, phrase_for, records
from test_schemas import validator_for

from patchproof import pack_approval as pa
from patchproof.core.approvals import (
    ApprovalStore,
    ReviewDecision,
    check_approval,
    create_approval,
    current_approval,
)

FIRST = datetime(2026, 10, 13, 5, 24, 44, tzinfo=UTC)
LATER = datetime(2026, 10, 13, 9, 0, tzinfo=UTC)
GOOD_RATIONALE = ("I reviewed the eight synthetic authorization checks, the fixture, the marker-based evidence and "
                  "the functional controls. Synthetic unit-test approval.")
GOOD_SCOPE = "Limited to the synthetic test pack 1.0.0 and its bound profile and verifier. Authorizes no run."


@pytest.fixture
def s(tmp_path: Path) -> Synthetic:
    return build(tmp_path)


def _incident_approval(s: Synthetic) -> str:
    """The deficient original: the phrase typed into rationale and scope (written directly, as PP-007 allowed)."""
    review = pa.assemble_review(s.target)
    store = pa.provision_store(s.store_root)
    record = create_approval(review.bindings, ReviewDecision("Synthetic Owner", review.phrase, review.phrase,
                                                             review.phrase), supersedes=None, now=FIRST)
    store.save(record)
    return record.approval_id


def _snapshot(s: Synthetic) -> dict[str, tuple[str, int, int]]:
    out = {}
    for name in records(s):
        st = os.lstat(s.store_root / name)
        out[name] = (hashlib.sha256((s.store_root / name).read_bytes()).hexdigest(), st.st_mode, st.st_mtime_ns)
    return out


def _supersede(s: Synthetic, terminal: FakeTerminal | None = None) -> tuple[int, FakeTerminal]:
    terminal = terminal or FakeTerminal({**answers(phrase_for(s)), "Rationale": GOOD_RATIONALE,
                                         "Approval scope": GOOD_SCOPE})
    return pa.run_supersession(s.target, s.store_root, terminal, now=lambda: LATER), terminal


def _refused(s: Synthetic, message: str, terminal: FakeTerminal | None = None) -> FakeTerminal:
    before = _snapshot(s)
    code, term = _supersede(s, terminal)
    out = term.output()
    assert code == 2, out
    assert "NOT SUPERSEDED" in out and message in out, out
    assert "Nothing was written; the current approval is unchanged" in out
    assert "PACK APPROVAL SUPERSEDED" not in out
    assert _snapshot(s) == before
    return term


# ------------------------------------------------------------------ the successful replacement


def test_supersession_preserves_the_original_and_links_the_replacement(s: Synthetic) -> None:
    original = _incident_approval(s)
    before = _snapshot(s)
    code, term = _supersede(s)
    out = term.output()
    assert code == 0, out

    names = records(s)
    assert len(names) == 2 and f"{original}.json" in names
    assert {n: before[n] for n in before} == {n: _snapshot(s)[n] for n in before}  # byte-for-byte, mode, mtime

    store = ApprovalStore(s.store_root)
    history = store.records()
    new = current_approval(history.values(), pa.assemble_review(s.target).bindings.pack_id)
    assert new is not None and new.approval_id != original
    assert new.supersedes == original
    assert new.bindings == history[original].bindings
    assert new.rationale == GOOD_RATIONALE and new.scope == GOOD_SCOPE
    assert new.created_at == "2026-10-13T09:00:00Z"
    assert (os.lstat(s.store_root / f"{new.approval_id}.json").st_mode & 0o777) == 0o400
    assert validator_for("approval-record").is_valid(json.loads((s.store_root / f"{new.approval_id}.json").read_text()))

    inputs = pa.assemble_review(s.target).inputs
    assert check_approval(history.values(), inputs, approval_id=new.approval_id).status == "APPROVED"
    old = check_approval(history.values(), inputs, approval_id=original)
    assert (old.status, old.stale_fields) == ("APPROVAL_STALE", ("superseded",))

    assert "PACK APPROVAL SUPERSEDED" in out and new.approval_id in out and original in out
    assert "authorizes no run" in out


def test_the_current_record_and_its_statement_are_shown_before_any_prompt(s: Synthetic) -> None:
    original = _incident_approval(s)
    code, term = _supersede(s)
    assert code == 0
    first_prompt = next(i for i, (kind, _) in enumerate(term.transcript) if kind == "prompt")
    shown = "".join(t for kind, t in term.transcript[:first_prompt] if kind == "out")
    phrase = phrase_for(s)
    for text in (original, "2026-10-13T05:24:44Z", "Synthetic Owner", f"rationale     {phrase!r}",
                 f"scope         {phrase!r}", "is kept, unchanged", "Nothing is deleted", "NOT a run authorization",
                 "No vulnerability has been reproduced"):
        assert text in shown, text


def test_complete_history_survives_repeated_supersession_with_one_current(s: Synthetic) -> None:
    _incident_approval(s)
    assert _supersede(s)[0] == 0
    before = _snapshot(s)
    assert _supersede(s)[0] == 0
    after = _snapshot(s)
    assert len(after) == 3 and all(after[n] == v for n, v in before.items())
    history = ApprovalStore(s.store_root).records()
    current = current_approval(history.values(), pa.assemble_review(s.target).bindings.pack_id)
    assert current is not None
    chain = [current]
    while chain[-1].supersedes:
        chain.append(history[chain[-1].supersedes])
    assert len(chain) == 3 and chain[-1].supersedes is None  # one linear history, one current leaf


# ------------------------------------------------------------------ refusals write nothing


def test_stale_bindings_refuse_supersession(s: Synthetic) -> None:
    _incident_approval(s)
    readme = s.target.pack_dir / "README.md"
    readme.write_text(readme.read_text() + "\nChanged after approval.\n")
    s.rewrite_evidence()
    term = _refused(s, "APPROVAL_STALE")
    assert not any(kind == "prompt" for kind, _ in term.transcript)


def test_wrong_confirmation_refuses(s: Synthetic) -> None:
    _incident_approval(s)
    _refused(s, "does not match the phrase", FakeTerminal({**answers("APPROVE something else"),
                                                           "Rationale": GOOD_RATIONALE,
                                                           "Approval scope": GOOD_SCOPE}))


@pytest.mark.parametrize("field", ["Rationale", "Approval scope"])
@pytest.mark.parametrize("shape", ["exact", "case-and-spacing", "embedded"])
def test_confirmation_text_as_rationale_or_scope_is_refused(s: Synthetic, field: str, shape: str) -> None:
    _incident_approval(s)
    phrase = phrase_for(s)
    value = {"exact": phrase, "case-and-spacing": "  " + phrase.lower().replace(" ", "   ") + " ",
             "embedded": f"Approved. {phrase}"}[shape]
    terminal = FakeTerminal({**answers(phrase), "Rationale": GOOD_RATIONALE, "Approval scope": GOOD_SCOPE,
                             field: value})
    _refused(s, "contains the confirmation phrase", terminal)


def test_the_first_approval_also_refuses_the_phrase_as_rationale(s: Synthetic) -> None:
    phrase = phrase_for(s)
    for field in ("Rationale", "Approval scope"):
        terminal = FakeTerminal({**answers(phrase), field: phrase})
        code = pa.run_approval(s.target, s.store_root, terminal, now=lambda: LATER)
        assert code == 2 and "contains the confirmation phrase" in terminal.output()
        assert "Nothing was written" in terminal.output() and "PACK APPROVED" not in terminal.output()
        assert records(s) == []


def test_empty_statement_and_ended_input_refuse(s: Synthetic) -> None:
    _incident_approval(s)
    _refused(s, "is required", FakeTerminal({**answers(phrase_for(s)), "Rationale": "  ",
                                             "Approval scope": GOOD_SCOPE}))
    _refused(s, "input ended", FakeTerminal({"Your name": "Synthetic Owner"}))


def test_no_store_and_no_current_approval_refuse_without_creating_anything(s: Synthetic) -> None:
    _refused(s, "no approval store")
    assert not s.store_root.exists()
    pa.provision_store(s.store_root)
    _refused(s, "no current approval to supersede")


def test_a_store_change_during_the_review_refuses(s: Synthetic) -> None:
    _incident_approval(s)

    def concurrent_supersession() -> None:
        store = ApprovalStore(s.store_root)
        current = current_approval(store.records().values(), pa.assemble_review(s.target).bindings.pack_id)
        review = pa.assemble_review(s.target)
        store.save(create_approval(review.bindings, ReviewDecision("Other", "Other rationale.", "Other scope.",
                                                                   review.phrase), supersedes=current, now=LATER))

    terminal = FakeTerminal({**answers(phrase_for(s)), "Rationale": GOOD_RATIONALE, "Approval scope": GOOD_SCOPE},
                            on_prompt={"Confirmation": concurrent_supersession})
    code, term = _supersede(s, terminal)
    assert code == 2 and "store changed during the review" in term.output()
    assert len(records(s)) == 2  # the concurrent record only; nothing from this run


def test_a_binding_change_during_the_review_refuses(s: Synthetic) -> None:
    _incident_approval(s)

    def change() -> None:
        readme = s.target.pack_dir / "README.md"
        readme.write_text(readme.read_text() + "\nChanged during review.\n")
        s.rewrite_evidence()

    target = s.target
    terminal = FakeTerminal({**answers(phrase_for(s)), "Rationale": GOOD_RATIONALE, "Approval scope": GOOD_SCOPE},
                            on_prompt={"Confirmation": change})
    before = _snapshot(s)
    code = pa.run_supersession(target, s.store_root, terminal, now=lambda: LATER)
    assert code == 2 and "NOT SUPERSEDED" in terminal.output() and _snapshot(s) == before


def test_the_pre_write_binding_recheck_refuses_a_different_binding_set(s: Synthetic,
                                                                       monkeypatch: pytest.MonkeyPatch) -> None:
    """With a pinned target any real change already fails assembly; this reaches the equality check itself."""
    _incident_approval(s)
    real = pa.assemble_review
    calls: list[pa.ApprovalTarget] = []

    def second_call_differs(target: pa.ApprovalTarget) -> pa.Review:
        calls.append(target)
        review = real(target)
        if len(calls) == 2:
            return replace(review, bindings=review.bindings.model_copy(update={"verifier_plugin_version": "9.9.9"}))
        return review

    monkeypatch.setattr(pa, "assemble_review", second_call_differs)
    _refused(s, "a binding changed between review and confirmation")


# ------------------------------------------------------------------ failures never corrupt the current state


def test_a_failed_write_leaves_the_original_current(s: Synthetic, monkeypatch: pytest.MonkeyPatch) -> None:
    original = _incident_approval(s)

    def failing_save(self: ApprovalStore, record: object) -> Path:
        raise OSError("synthetic disk failure")

    monkeypatch.setattr(ApprovalStore, "save", failing_save)
    _refused(s, "synthetic disk failure")
    monkeypatch.undo()
    history = ApprovalStore(s.store_root).records()
    current = current_approval(history.values(), pa.assemble_review(s.target).bindings.pack_id)
    assert current is not None and current.approval_id == original
    assert check_approval(history.values(), pa.assemble_review(s.target).inputs).status == "APPROVED"


def test_a_failure_after_the_write_is_reported_and_history_stays_intact(s: Synthetic,
                                                                         monkeypatch: pytest.MonkeyPatch) -> None:
    original = _incident_approval(s)
    before = _snapshot(s)
    real = pa.assemble_review
    calls: list[pa.ApprovalTarget] = []

    def third_call_fails(target: pa.ApprovalTarget) -> pa.Review:
        calls.append(target)
        if len(calls) == 3:  # review, pre-write recompute, post-write revalidation
            raise pa.ApprovalBlocked("synthetic revalidation failure")
        return real(target)

    terminal = FakeTerminal({**answers(phrase_for(s)), "Rationale": GOOD_RATIONALE, "Approval scope": GOOD_SCOPE})
    monkeypatch.setattr(pa, "assemble_review", third_call_fails)
    code = pa.run_supersession(s.target, s.store_root, terminal, now=lambda: LATER)
    out = terminal.output()
    assert code == 4 and "FAILED VERIFICATION: synthetic revalidation failure" in out
    assert "PACK APPROVAL SUPERSEDED" not in out
    after = _snapshot(s)
    assert len(after) == 2 and after[f"{original}.json"] == before[f"{original}.json"]


def test_a_tampered_original_is_detected_after_the_write(s: Synthetic, monkeypatch: pytest.MonkeyPatch) -> None:
    _incident_approval(s)
    real = pa._record_bytes
    calls: list[int] = []

    def tampered_view(store: ApprovalStore) -> dict[str, tuple[bytes, int]]:
        calls.append(1)
        found = real(store)
        if len(calls) == 3:  # the post-write comparison
            return {name: (data + b" ", mode) for name, (data, mode) in found.items()}
        return found

    monkeypatch.setattr(pa, "_record_bytes", tampered_view)
    code, term = _supersede(s)
    assert code == 4 and "no longer byte-for-byte identical" in term.output()
    assert "PACK APPROVAL SUPERSEDED" not in term.output()


# ------------------------------------------------------------------ the entry point is interactive only


def _run_module(tmp_path: Path, *args: str, env_extra: dict[str, str] | None = None,
                stdin: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    home = _private(tmp_path / "home")
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "LC_ALL": "C.UTF-8", **(env_extra or {})}
    return subprocess.run([sys.executable, "-I", "-m", "patchproof.pack_approval_supersede", *args], input=stdin,
                          env=env, capture_output=True, timeout=60, cwd=ROOT, check=False)


@pytest.mark.parametrize(("args", "env", "stdin", "message"), [
    ((), None, b"Me\nWhy\nScope\nAPPROVE papertrail-document-access 1.0.0 a4c4ce48d5d2\n", "interactive terminal"),
    (("--confirm", "APPROVE papertrail-document-access 1.0.0 a4c4ce48d5d2"), None, b"", "takes no arguments"),
    ((), {"PATCHPROOF_RATIONALE": "x"}, b"", "environment variables are not accepted"),
])
def test_noninteractive_supersession_is_refused(tmp_path: Path, args: tuple[str, ...], env: dict[str, str] | None,
                                                stdin: bytes, message: str) -> None:
    result = _run_module(tmp_path, *args, env_extra=env, stdin=stdin)
    assert result.returncode == 2
    assert message in result.stderr.decode() and "NOT SUPERSEDED" in result.stderr.decode()
    assert "Nothing was read or written" in result.stderr.decode()
    assert b"SUPERSEDED." not in result.stdout
    assert not any(p.name == "approvals" for p in (tmp_path / "home").rglob("*"))


def test_module_in_a_terminal_with_no_evidence_is_blocked(tmp_path: Path) -> None:
    """End to end in a pseudo-terminal, with HOME pointing at an empty temporary directory."""
    home = _private(tmp_path / "home")
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(ROOT)
        os.execve(sys.executable, [sys.executable, "-I", "-m", "patchproof.pack_approval_supersede"],
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
    assert b"NOT SUPERSEDED: collection evidence directory is missing" in out
    assert not any(p.name == "approvals" for p in home.rglob("*"))
