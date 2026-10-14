"""PP-008: the owner-operated pack-approval entry point, Docker-free.

Every approval written here is SYNTHETIC: it approves a renamed copy of the PaperTrail pack
(`synthetic-approval-test`), uses synthetic collection evidence and a "Synthetic Reviewer",
and is written to a temporary store. No PaperTrail approval is produced, the real approval
store is never opened, and no pack module is imported.
"""

from __future__ import annotations

import hashlib
import json
import os
import pty
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from test_schemas import validator_for

from patchproof import pack_approval as pa
from patchproof.core.approvals import ApprovalCheck, ApprovalStore, BindingInputs, check_approval
from patchproof.core.records.pack import ApprovalRecord
from patchproof.packs.validation import validate_pack
from patchproof.runner.policy import ImageId
from patchproof.runner.profiles import PAPERTRAIL_PROFILE_SHA256
from patchproof.runner.run_plan import APPROVED_RUN_IMAGES, PLUGIN_VERSION, ApprovedRunImage
from patchproof.runner.run_policy import RunRole, collect_command

ROOT = Path(__file__).resolve().parents[2]
PACK_DIR = ROOT / "examples" / "packs" / "papertrail-document-access"
REPO_PROFILE = ROOT / "profiles" / "papertrail-reference-1.0.0.json"
SYNTHETIC_PACK_ID = "synthetic-approval-test"
NOW = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)


def _private(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return Path(os.path.realpath(path))


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass
class Synthetic:
    root: Path
    target: pa.ApprovalTarget
    store_root: Path

    def rewrite_evidence(self, order: list[int] | None = None) -> None:
        """(Re)write collection evidence for the current pack bytes and repin its hashes."""
        pack = validate_pack(self.target.pack_dir)
        tests = [{"id": t.id, "nodeid": t.nodeid} for t in pack.manifest.tests]
        if order is not None:
            tests = [tests[i] for i in order]
        stdout = json.dumps({"tests": tests}, separators=(",", ":")).encode() + b"\n"
        result = {
            "step": "C2", "synthetic": False, "verdict": "PASS", "exit_code": 0, "termination": "EXITED",
            "timed_out": False, "stdout_truncated": False, "oom_killed": False, "gate_passed": True,
            "pack_verified_before": True, "pack_verified_after": True,
            "image": APPROVED_RUN_IMAGES[1].image.value, "pack_tree_sha256": pack.pack_tree_sha256,
            "manifest_sha256": pack.manifest_sha256, "stdout_bytes": len(stdout),
            "command": list(collect_command(tuple(f"/pack/{p}" for p in pack.test_files))),
            "facts": {"collected": tests},
        }
        raw = json.dumps(result, indent=2).encode()
        evidence = self.target.evidence_dir
        for name, data in (("stdout.bin", stdout), ("result.json", raw)):
            (evidence / name).unlink(missing_ok=True)
            (evidence / name).write_bytes(data)
        self.target = replace(self.target, evidence_stdout_sha256=_sha(stdout), evidence_result_sha256=_sha(raw))


def build(tmp_path: Path) -> Synthetic:
    root = _private(tmp_path / "work")
    pack_dir = root / "pack"
    shutil.copytree(PACK_DIR, pack_dir)
    manifest = json.loads((pack_dir / "pack.json").read_text())
    manifest["pack_id"] = SYNTHETIC_PACK_ID
    (pack_dir / "pack.json").write_text(json.dumps(manifest, indent=2) + "\n")
    profiles = root / "project" / "profiles"
    profiles.mkdir(parents=True)
    shutil.copy(REPO_PROFILE, profiles / REPO_PROFILE.name)
    plugin = root / "plugin.py"
    plugin.write_text(f'from typing import Final\n\nPLUGIN_VERSION: Final = "{PLUGIN_VERSION}"\n')
    evidence = _private(root / "evidence" / "C2")
    data = _private(root / "data")
    target = pa.ApprovalTarget(pack_dir=pack_dir, pack_id=SYNTHETIC_PACK_ID, pack_version="1.0.0",
                               profile_path=profiles / REPO_PROFILE.name, profile_sha256=PAPERTRAIL_PROFILE_SHA256,
                               evidence_dir=evidence, evidence_stdout_sha256="", evidence_result_sha256="",
                               plugin_source=plugin)
    synthetic = Synthetic(root=root, target=target, store_root=data / "approvals")
    synthetic.rewrite_evidence()
    return synthetic


@dataclass
class FakeTerminal:
    """Scripted answers. `on_prompt` runs before an answer is returned (to simulate changes)."""

    answers: dict[str, str]
    on_prompt: dict[str, Callable[[], None]] = field(default_factory=dict)
    transcript: list[tuple[str, str]] = field(default_factory=list)

    def write(self, text: str) -> None:
        self.transcript.append(("out", text))

    def read_line(self, prompt: str) -> str:
        self.transcript.append(("prompt", prompt))
        for key, hook in self.on_prompt.items():
            if prompt.startswith(key):
                hook()
        for key, answer in self.answers.items():
            if prompt.startswith(key):
                return answer
        raise EOFError

    def output(self) -> str:
        return "".join(t for kind, t in self.transcript if kind == "out")


def answers(phrase: str) -> dict[str, str]:
    return {"Your name": "Synthetic Reviewer",
            "Rationale": "Synthetic unit-test approval of the reviewed checks and their bindings.",
            "Approval scope": "Unit tests only; not a PaperTrail approval.", "Confirmation": phrase}


def phrase_for(s: Synthetic) -> str:
    return pa.assemble_review(s.target).phrase


def approve(s: Synthetic, terminal: FakeTerminal | None = None) -> tuple[int, FakeTerminal]:
    terminal = terminal or FakeTerminal(answers(phrase_for(s)))
    return pa.run_approval(s.target, s.store_root, terminal, now=lambda: NOW), terminal


def records(s: Synthetic) -> list[str]:
    return sorted(os.listdir(s.store_root)) if s.store_root.exists() else []


@pytest.fixture
def s(tmp_path: Path) -> Synthetic:
    return build(tmp_path)


# ------------------------------------------------------------------ the real defaults


def test_real_target_points_at_the_repository_and_private_paths() -> None:
    target = pa.papertrail_target()
    assert target.pack_dir == ROOT / "examples/packs/papertrail-document-access"
    assert target.profile_path == REPO_PROFILE and target.profile_sha256 == PAPERTRAIL_PROFILE_SHA256
    assert target.plugin_source == ROOT / "verifier/patchproof_verifier/plugin.py"
    assert pa.approval_store_root().name == "approvals"
    assert pa.approval_store_root().parent == target.evidence_dir.parents[2]
    if sys.platform == "darwin":
        assert str(pa.approval_store_root()).endswith("/Library/Application Support/PatchProof/approvals")


# ------------------------------------------------------------------ the interactive gate


def _run_module(tmp_path: Path, *args: str, env_extra: dict[str, str] | None = None,
                stdin: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    home = _private(tmp_path / "home")
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "LC_ALL": "C.UTF-8", **(env_extra or {})}
    return subprocess.run([sys.executable, "-I", "-m", "patchproof.pack_approval", *args], input=stdin, env=env,
                          capture_output=True, timeout=60, cwd=ROOT, check=False)


def _assert_refused(result: subprocess.CompletedProcess[bytes], message: str, tmp_path: Path) -> None:
    assert result.returncode == 2
    assert message in result.stderr.decode()
    assert "Nothing was read or written" in result.stderr.decode()
    assert b"PACK APPROVED" not in result.stdout + result.stderr
    assert not any(p.name == "approvals" for p in (tmp_path / "home").rglob("*"))


def test_piped_confirmation_is_refused(s: Synthetic, tmp_path: Path) -> None:
    result = _run_module(tmp_path, stdin=b"Me\nWhy\nScope\nAPPROVE papertrail-document-access 1.0.0 a4c4ce48d5d2\n")
    _assert_refused(result, "interactive terminal", tmp_path)


def test_confirmation_arguments_are_refused(tmp_path: Path) -> None:
    result = _run_module(tmp_path, "--confirm", "APPROVE papertrail-document-access 1.0.0 a4c4ce48d5d2")
    _assert_refused(result, "takes no arguments", tmp_path)


def test_confirmation_environment_variables_are_refused(tmp_path: Path) -> None:
    result = _run_module(tmp_path, env_extra={
        "PATCHPROOF_CONFIRMATION": "APPROVE papertrail-document-access 1.0.0 a4c4ce48d5d2"})
    _assert_refused(result, "environment variables are not accepted", tmp_path)


def test_gate_rules_in_process() -> None:
    with pytest.raises(pa.NotInteractive, match="no arguments"):
        pa.require_interactive(["prog", "x"], {})
    with pytest.raises(pa.NotInteractive, match="environment"):
        pa.require_interactive(["prog"], {"patchproof_reviewer": "x"})
    read_fd, write_fd = os.pipe()
    try:
        with pytest.raises(pa.NotInteractive, match="interactive terminal"):
            pa.require_interactive(["prog"], {}, stdin_fd=read_fd, stdout_fd=write_fd)
    finally:
        os.close(read_fd)
        os.close(write_fd)


def _in_pty(child: Callable[[], int]) -> int:
    pid, fd = pty.fork()
    if pid == 0:  # child: a new session whose controlling terminal is the pty
        code = 1
        try:
            code = child()
        finally:
            os._exit(code)
    try:
        while True:
            try:
                if not os.read(fd, 1024):
                    break
            except OSError:
                break
    finally:
        _, status = os.waitpid(pid, 0)
        os.close(fd)
    return os.waitstatus_to_exitcode(status)


def test_a_foreground_controlling_terminal_is_accepted() -> None:
    def child() -> int:
        pa.require_interactive(["prog"], {})
        return 0
    assert _in_pty(child) == 0


def test_a_terminal_that_is_not_in_the_foreground_is_refused() -> None:
    def child() -> int:
        grandchild = os.fork()
        if grandchild == 0:  # same terminal, but a background process group
            code = 1
            try:
                os.setpgid(0, 0)
                pa.require_interactive(["prog"], {})
            except pa.NotInteractive:
                code = 0
            finally:
                os._exit(code)
        _, status = os.waitpid(grandchild, 0)
        return os.waitstatus_to_exitcode(status)
    assert _in_pty(child) == 0


def test_module_in_a_terminal_with_no_evidence_is_blocked_before_the_store(tmp_path: Path) -> None:
    """End to end in a pseudo-terminal, with HOME pointing at an empty temporary directory."""
    home = _private(tmp_path / "home")
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(ROOT)
        os.execve(sys.executable, [sys.executable, "-I", "-m", "patchproof.pack_approval"],
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
    assert b"NOT APPROVED: collection evidence directory is missing" in out
    assert b"Nothing was written" in out
    assert not any(p.name == "approvals" for p in home.rglob("*"))


# ------------------------------------------------------------------ prerequisites block approval


def _blocked(s: Synthetic, message: str, terminal: FakeTerminal | None = None) -> FakeTerminal:
    code, term = approve(s, terminal or FakeTerminal(answers("APPROVE x 1.0.0 000000000000")))
    assert code == 2, term.output()
    assert "NOT APPROVED" in term.output() and message in term.output(), term.output()
    assert "Nothing was written" in term.output()
    assert records(s) == []
    return term


def test_missing_profile_blocks(s: Synthetic) -> None:
    s.target.profile_path.unlink()
    _blocked(s, "profile file is missing")


def test_invalid_profile_blocks(s: Synthetic) -> None:
    doc = json.loads(s.target.profile_path.read_text())
    doc["docker_args"] = ["--privileged"]
    s.target.profile_path.write_text(json.dumps(doc))
    _blocked(s, "not a valid execution-profile")


def test_changed_profile_hash_blocks(s: Synthetic) -> None:
    s.target = replace(s.target, profile_sha256="sha256:" + "1" * 64)
    _blocked(s, "differs from the expected binding")


def test_profile_log_and_cancellation_values_inconsistent_with_the_runner_block(s: Synthetic) -> None:
    for dotted, value in (("logging.max_file_bytes", 1048576), ("logging.max_files", 1),
                          ("timeouts.cancellation_grace_seconds", 10)):
        doc = json.loads(REPO_PROFILE.read_text())
        group, key = dotted.split(".")
        doc[group][key] = value
        s.target.profile_path.write_text(json.dumps(doc))
        _blocked(s, f"differ from the enforced runtime policy: {dotted}")


def test_a_different_source_scope_cannot_reuse_the_profile(s: Synthetic) -> None:
    doc = json.loads(REPO_PROFILE.read_text())
    doc["source_scope"]["include"] = ["papertrail"]
    s.target.profile_path.write_text(json.dumps(doc))
    _blocked(s, "differs from the expected binding")


def test_changed_pack_bytes_block(s: Synthetic) -> None:
    readme = s.target.pack_dir / "README.md"
    readme.write_text(readme.read_text() + "\nChanged after collection.\n")
    _blocked(s, "collection result does not establish this pack's collection: pack_tree_sha256")


def test_changed_collection_order_blocks(s: Synthetic) -> None:
    s.rewrite_evidence(order=[1, 0, 2, 3, 4, 5, 6, 7])
    _blocked(s, "collected order differs from the manifest order")


def test_tampered_collection_evidence_blocks(s: Synthetic) -> None:
    (s.target.evidence_dir / "stdout.bin").write_bytes(b'{"tests":[]}\n')
    _blocked(s, "differs from the recorded C2 evidence hash")


def test_evidence_must_be_private_and_not_a_symlink(s: Synthetic) -> None:
    os.chmod(s.target.evidence_dir, 0o755)
    _blocked(s, "must be private (0700)")
    os.chmod(s.target.evidence_dir, 0o700)
    link = s.root / "evidence-link"
    link.symlink_to(s.target.evidence_dir)
    s.target = replace(s.target, evidence_dir=link)
    _blocked(s, "absolute and canonical")


def test_changed_verifier_image_identity_blocks(s: Synthetic) -> None:
    other = ApprovedRunImage(RunRole.VERIFIER, ImageId("sha256:" + "0123456789abcdef" * 4),
                             APPROVED_RUN_IMAGES[1].env, None)
    s.target = replace(s.target, approved_images=(APPROVED_RUN_IMAGES[0], other))
    _blocked(s, "not the approved verifier run image")


def test_stale_plugin_version_blocks(s: Synthetic) -> None:
    s.target.plugin_source.write_text('from typing import Final\n\nPLUGIN_VERSION: Final = "0.2.0"\n')
    _blocked(s, "declares 0.2.0, the runner expects 0.1.0")


def test_wrong_pack_identity_blocks(s: Synthetic) -> None:
    s.target = replace(s.target, pack_id="papertrail-document-access")
    _blocked(s, "pack ID or version differs")


def test_wrong_phrase_writes_nothing(s: Synthetic) -> None:
    phrase = phrase_for(s)
    _blocked(s, "does not match the phrase", FakeTerminal(answers(phrase.lower())))
    _blocked(s, "does not match the phrase", FakeTerminal(answers(phrase + " ")))


def test_ended_input_writes_nothing(s: Synthetic) -> None:
    code, term = approve(s, FakeTerminal({"Your name": "Synthetic Reviewer"}))
    assert code == 2 and "input ended" in term.output() and records(s) == []


def test_empty_answers_write_nothing(s: Synthetic) -> None:
    _blocked(s, "is required", FakeTerminal({**answers(phrase_for(s)), "Rationale": "   "}))


def test_changing_the_pack_between_review_and_record_creation_is_detected(s: Synthetic) -> None:
    def change() -> None:
        readme = s.target.pack_dir / "README.md"
        readme.write_text(readme.read_text() + "\nChanged during review.\n")
        s.rewrite_evidence()  # even with matching new evidence, the reviewed bindings differ

    target_before = s.target
    terminal = FakeTerminal(answers(phrase_for(s)), on_prompt={"Confirmation": change})
    code = pa.run_approval(target_before, s.store_root, terminal, now=lambda: NOW)
    assert code == 2 and "NOT APPROVED" in terminal.output() and records(s) == []


def test_changing_the_profile_between_review_and_record_creation_is_detected(s: Synthetic) -> None:
    def change() -> None:
        doc = json.loads(REPO_PROFILE.read_text())
        doc["timeouts"]["readiness_seconds"] = 29
        s.target.profile_path.write_text(json.dumps(doc))

    _blocked(s, "differ from the enforced runtime policy",
             FakeTerminal(answers(phrase_for(s)), on_prompt={"Confirmation": change}))


# ------------------------------------------------------------------ the approval store


def test_store_symlink_is_refused(s: Synthetic) -> None:
    real = _private(s.root / "elsewhere")
    s.store_root.symlink_to(real)
    _blocked(s, "approval store must be a directory owned by you with mode 0700")
    assert os.listdir(real) == []


def test_store_with_loose_permissions_is_refused_not_repaired(s: Synthetic) -> None:
    s.store_root.mkdir(mode=0o755)
    os.chmod(s.store_root, 0o755)
    _blocked(s, "mode 0700")
    assert (os.stat(s.store_root).st_mode & 0o777) == 0o755


def test_store_parent_writable_by_others_is_refused(s: Synthetic) -> None:
    os.chmod(s.store_root.parent, 0o777)
    try:
        _blocked(s, "not writable by others")
        assert not s.store_root.exists()
    finally:
        os.chmod(s.store_root.parent, 0o700)


def test_store_is_provisioned_private(s: Synthetic) -> None:
    store = pa.provision_store(s.store_root)
    st = os.lstat(s.store_root)
    assert (st.st_mode & 0o777) == 0o700 and st.st_uid == os.getuid()
    assert store.identity == (st.st_dev, st.st_ino) and store.records() == {}
    assert pa.provision_store(s.store_root).identity == store.identity  # idempotent, never recreated


# ------------------------------------------------------------------ successful synthetic approval


def test_complete_binding_set_is_displayed_before_confirmation(s: Synthetic) -> None:
    review = pa.assemble_review(s.target)
    code, term = approve(s)
    assert code == 0
    confirm_at = next(i for i, (kind, text) in enumerate(term.transcript)
                      if kind == "prompt" and text.startswith("Confirmation"))
    shown = "".join(text for kind, text in term.transcript[:confirm_at] if kind == "out")
    b = review.bindings
    for value in (b.pack_id, b.pack_version, b.pack_schema_version, b.manifest_sha256, b.pack_tree_sha256,
                  b.verifier_image_id, b.verifier_plugin_version, b.profile_id, b.profile_sha256, review.phrase):
        assert value in shown
    for test in b.expected_collection:
        assert test.id in shown and test.nodeid in shown
    assert shown.index("AUTH-001") < shown.index("AUTH-002") < shown.index("FUNC-004")
    for line in pa.profile_document(review.profile).splitlines():
        assert line in shown
    for text in ("NOT a run authorization", "No vulnerability has been reproduced", "local-assertion-unverified",
                 "procedural control", "INCONCLUSIVE", "deny-everything"):
        assert text in shown


def test_successful_synthetic_approval_uses_the_pp007_record(s: Synthetic) -> None:
    code, term = approve(s)
    assert code == 0, term.output()
    names = records(s)
    assert len(names) == 1
    path = s.store_root / names[0]
    assert (os.lstat(path).st_mode & 0o777) == 0o400
    doc = json.loads(path.read_text())
    assert validator_for("approval-record").is_valid(doc)
    store = ApprovalStore(s.store_root)
    (record,) = store.records().values()
    review = pa.assemble_review(s.target)
    assert record.bindings == review.bindings and record.supersedes is None
    assert record.bindings.pack_id == SYNTHETIC_PACK_ID
    assert record.reviewer.asserted_identity == "Synthetic Reviewer"
    assert record.reviewer.basis == "local-assertion-unverified"
    assert record.created_at == "2026-10-12T12:00:00Z"
    assert check_approval(store.records().values(), review.inputs, approval_id=record.approval_id).status == "APPROVED"
    assert f"PACK APPROVED: {record.approval_id}" in term.output() and "authorizes no run" in term.output()


def test_a_failed_post_write_check_is_never_reported_as_approved(s: Synthetic,
                                                                  monkeypatch: pytest.MonkeyPatch) -> None:
    real = check_approval

    def final_stale(history: Iterable[ApprovalRecord], inputs: BindingInputs, *,
                    approval_id: str | None = None) -> ApprovalCheck:
        result = real(history, inputs, approval_id=approval_id)
        return replace(result, status="APPROVAL_STALE", stale_fields=("synthetic",)) if approval_id else result

    monkeypatch.setattr(pa, "check_approval", final_stale)
    code, term = approve(s)
    assert code == 4 and "FAILED VERIFICATION" in term.output() and "PACK APPROVED" not in term.output()
    assert len(records(s)) == 1


def test_an_error_after_the_write_is_never_reported_as_approved(s: Synthetic,
                                                                monkeypatch: pytest.MonkeyPatch) -> None:
    real = pa.assemble_review
    calls: list[pa.ApprovalTarget] = []

    def third_call_fails(target: pa.ApprovalTarget) -> pa.Review:
        calls.append(target)
        if len(calls) == 3:  # review, pre-write recompute, post-write revalidation
            raise pa.ApprovalBlocked("synthetic revalidation failure")
        return real(target)

    terminal = FakeTerminal(answers(phrase_for(s)))
    monkeypatch.setattr(pa, "assemble_review", third_call_fails)
    code = pa.run_approval(s.target, s.store_root, terminal, now=lambda: NOW)
    out = terminal.output()
    assert code == 4 and "FAILED VERIFICATION: synthetic revalidation failure" in out
    assert "PACK APPROVED" not in out and "Nothing was written" not in out
    assert len(records(s)) == 1


def test_rerunning_with_unchanged_bindings_writes_nothing(s: Synthetic) -> None:
    assert approve(s)[0] == 0
    before = records(s)
    code, term = approve(s)
    assert code == 3 and "already approves exactly these bindings" in term.output()
    assert records(s) == before


def test_existing_history_is_preserved_by_supersession(s: Synthetic) -> None:
    assert approve(s)[0] == 0
    (first_name,) = records(s)
    first_bytes = (s.store_root / first_name).read_bytes()
    readme = s.target.pack_dir / "README.md"
    readme.write_text(readme.read_text() + "\nRevised.\n")
    s.rewrite_evidence()
    stale = check_approval(ApprovalStore(s.store_root).records().values(), pa.assemble_review(s.target).inputs)
    assert stale.status == "APPROVAL_STALE" and "pack_tree_sha256" in stale.stale_fields
    code, term = approve(s)
    assert code == 0, term.output()
    assert f"Supersedes: {first_name.removesuffix('.json')}" in term.output()
    names = records(s)
    assert len(names) == 2 and first_name in names
    assert (s.store_root / first_name).read_bytes() == first_bytes
    store = ApprovalStore(s.store_root)
    current = store.current(SYNTHETIC_PACK_ID)
    assert current is not None and current.supersedes == first_name.removesuffix(".json")


def test_an_unexpected_store_entry_blocks_without_writing(s: Synthetic) -> None:
    pa.provision_store(s.store_root)
    (s.store_root / "notes.txt").write_text("x")
    code, term = approve(s)
    assert code == 2 and "unexpected entry" in term.output()
    assert records(s) == ["notes.txt"]


def test_selftest_pack_can_never_be_approved(s: Synthetic) -> None:
    manifest = json.loads((s.target.pack_dir / "pack.json").read_text())
    manifest["pack_id"] = "verifier-selftest"
    (s.target.pack_dir / "pack.json").write_text(json.dumps(manifest, indent=2) + "\n")
    s.target = replace(s.target, pack_id="verifier-selftest")
    s.rewrite_evidence()
    _blocked(s, "can never be approved", FakeTerminal(answers(phrase_for(s))))
