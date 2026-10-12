"""PP-006: PaperTrail reference repository, fixture profile material, and ground truth.

Everything here is Docker-free, and PaperTrail is never imported or executed: its sources
are read as bytes and parsed with `ast`. A small interpreter evaluates only the restricted
expression language of `papertrail/authz.py` and refuses everything else, so the declared
expectations in `examples/papertrail/reference-fixture.json` are checked against the
source-level design of each revision without running target code (INV-01, ADR-003).

Git is used in two ways. The generator writes objects itself and never runs Git. The tests
then check those objects with the reviewed Git binary: read-only commands on the generated
repository (`fsck --strict`, `cat-file`, `for-each-ref`), and an independent rebuild with
ordinary Git porcelain in a separate temporary repository to confirm the commit IDs.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
import subprocess
import sys
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from _git_fixtures import fingerprint, git, git_binary, private_dir
from _verdict_builder import resync, verified_input
from _verdict_builder import run as run_verdict
from patchproof.git.errors import SourceError
from patchproof.git.paths import SourceScope, is_secret_path
from patchproof.git.repository import register_repository, resolve_revision
from patchproof.git.snapshot import canonical_json, create_snapshot
from patchproof.reference import gitobjects, papertrail
from patchproof.reference.__main__ import main as cli_main
from patchproof.reference.gitobjects import FixtureGenerationError, Signature

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "papertrail"
GROUND_TRUTH_PATH = EXAMPLE / "reference-fixture.json"
GROUND_TRUTH: dict[str, Any] = json.loads(GROUND_TRUTH_PATH.read_text())
FIXTURE_DATA: dict[str, Any] = json.loads(
    (EXAMPLE / "template" / "fixtures" / "synthetic" / "synthetic-documents-v1.json").read_text())
DOC = ROOT / "docs" / "architecture" / "papertrail-reference.md"
KEYS = ("vulnerable", "inadequate", "correct", "deny-all")
SCOPE = SourceScope.of(GROUND_TRUTH["target"]["source_scope"]["include"])
CHECKS = {c["id"]: c for c in GROUND_TRUTH["checks"]}
CALLERS = {c["caller_id"]: c for c in GROUND_TRUTH["callers"]}
USERS = {u["user_id"]: u for u in FIXTURE_DATA["users"]}
DOCUMENTS = {d["document_id"]: d for d in FIXTURE_DATA["documents"]}


def _files(rev: str) -> dict[str, bytes]:
    return papertrail.revision_files()[rev]


@pytest.fixture(scope="module")
def generated(tmp_path_factory: pytest.TempPathFactory) -> papertrail.GeneratedRepository:
    base = private_dir(tmp_path_factory.mktemp("papertrail"))
    return papertrail.generate_reference_repository(base / "repo")


def _read_git(root: Path, *args: str) -> str:
    """Read-only Git query against the generated repository."""
    return git(root, *args).decode()


# ------------------------------------------------------------ static authz interpreter


class Unsupported(Exception):
    pass


_FIELDS = {"user_id", "role", "owner_id", "reader_roles", "document_id"}


def load_policy(source: str) -> Callable[[dict[str, Any] | None, dict[str, Any]], bool]:
    """Interpret `can_read_document` from authz.py source. Never imports or executes it."""
    module = ast.parse(source)
    constants: dict[str, frozenset[str]] = {}
    function: ast.FunctionDef | None = None
    for node in module.body:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            continue
        if isinstance(node, ast.ImportFrom) and node.module in ("__future__", "papertrail.fixtures"):
            continue
        if (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Call) and ast.unparse(node.value.func) == "frozenset"
                and len(node.value.args) == 1 and isinstance(node.value.args[0], ast.Set)
                and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.value.args[0].elts)):
            constants[node.targets[0].id] = frozenset(e.value for e in node.value.args[0].elts)
            continue
        if (isinstance(node, ast.FunctionDef) and node.name == "can_read_document" and not node.decorator_list
                and [a.arg for a in node.args.args] == ["user", "document"] and function is None):
            function = node
            continue
        raise Unsupported(f"module statement {ast.unparse(node)[:60]!r}")
    if function is None:
        raise Unsupported("can_read_document is not defined")
    body = list(function.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]

    def evaluate(node: ast.expr, env: dict[str, Any]) -> Any:
        if isinstance(node, ast.Constant) and (node.value is None or isinstance(node.value, (bool, str))):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in env:
                return env[node.id]
            if node.id in constants:
                return constants[node.id]
            raise Unsupported(f"name {node.id}")
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.attr in _FIELDS:
            record = env.get(node.value.id)
            if record is None:
                raise Unsupported(f"attribute access on None: {node.value.id}.{node.attr}")
            return record[node.attr]
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            left, right = evaluate(node.left, env), evaluate(node.comparators[0], env)
            op = node.ops[0]
            if isinstance(op, ast.Is):
                return left is right
            if isinstance(op, ast.IsNot):
                return left is not right
            if isinstance(op, ast.Eq):
                return left == right
            if isinstance(op, ast.NotEq):
                return left != right
            if isinstance(op, ast.In):
                return left in right
            if isinstance(op, ast.NotIn):
                return left not in right
        if isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                return all(evaluate(v, env) for v in node.values)
            return any(evaluate(v, env) for v in node.values)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not evaluate(node.operand, env)
        raise Unsupported(f"expression {ast.unparse(node)[:60]!r}")

    def decide(user: dict[str, Any] | None, document: dict[str, Any]) -> bool:
        env = {"user": user, "document": document}
        for stmt in body:
            if isinstance(stmt, ast.Return) and stmt.value is not None:
                result = evaluate(stmt.value, env)
                assert isinstance(result, bool)
                return result
            if (isinstance(stmt, ast.If) and not stmt.orelse and len(stmt.body) == 1
                    and isinstance(stmt.body[0], ast.Return) and stmt.body[0].value is not None):
                if evaluate(stmt.test, env):
                    result = evaluate(stmt.body[0].value, env)
                    assert isinstance(result, bool)
                    return result
                continue
            raise Unsupported(f"statement {ast.unparse(stmt)[:60]!r}")
        raise Unsupported("can_read_document can return None")

    return decide


def policy(rev: str) -> Callable[[dict[str, Any] | None, dict[str, Any]], bool]:
    return load_policy(_files(rev)["papertrail/authz.py"].decode())


def derive_outcome(rev: str, check: dict[str, Any]) -> dict[str, Any]:
    """Expected outcome from app.py semantics (verified structurally below) and the authz decision."""
    caller = CALLERS[check["caller"]]
    marker = check["protected_marker"]
    if caller["authorization"] != "fixture-bearer":
        status = 401
        disclosed = False
    elif check["path"] == "/me":
        status, disclosed = 200, False
    else:
        document = DOCUMENTS[check["path"].removeprefix("/documents/")]
        allowed = policy(rev)(USERS[caller["user_id"]], document)
        status = 200 if allowed else 404
        disclosed = allowed and marker is not None and marker in document["content"]
    if check["kind"] == "security":
        semantic = "VIOLATION_CONFIRMED" if disclosed else "SECURE"
    else:
        wants_marker = marker is not None
        semantic = "PASS" if status == 200 and disclosed == wants_marker else "FAIL"
    return {"semantic": semantic, "status": status, "marker_disclosed": disclosed}


# ------------------------------------------------------------ determinism and identity


def test_generation_is_byte_for_byte_reproducible(tmp_path: Path, generated: papertrail.GeneratedRepository) -> None:
    again = papertrail.generate_reference_repository(private_dir(tmp_path / "w") / "repo")
    assert again.as_record() == generated.as_record()

    def tree(root: Path) -> dict[str, tuple[int, bytes | None]]:
        out: dict[str, tuple[int, bytes | None]] = {}
        for dirpath, _dirs, names in os.walk(root):
            for name in [".", *names]:
                full = Path(dirpath) / name if name != "." else Path(dirpath)
                st = os.lstat(full)
                out[full.relative_to(root).as_posix()] = (st.st_mode, full.read_bytes() if name != "." else None)
        return out

    assert tree(again.root) == tree(generated.root)


def test_recorded_identities_are_the_generated_ones(generated: papertrail.GeneratedRepository) -> None:
    record = generated.as_record()
    repo = GROUND_TRUTH["repository"]
    assert (record["object_format"], record["head"], record["generator_version"]) == (
        repo["object_format"], repo["head"], repo["generator_version"])
    keys = {r["commit_id"]: r["key"] for r in record["revisions"]}
    declared = [{k: r[k] for k in ("key", "tag", "tag_object_id", "commit_id", "tree_id", "parent")}
                for r in GROUND_TRUTH["revisions"]]
    actual = [{"key": r["key"], "tag": r["tag"], "tag_object_id": r["tag_object_id"], "commit_id": r["commit_id"],
               "tree_id": r["tree_id"], "parent": keys.get(r["parent_commit_id"] or "")} for r in record["revisions"]]
    assert actual == declared
    assert [r["key"] for r in declared] == list(KEYS)
    assert record["head_commit_id"] == declared[0]["commit_id"]


def test_real_git_accepts_every_object_and_ref(generated: papertrail.GeneratedRepository) -> None:
    root = generated.root
    assert _read_git(root, "fsck", "--strict", "--no-dangling", "--no-progress") == ""
    refs = _read_git(root, "for-each-ref", "--format=%(refname) %(objecttype) %(*objectname)").splitlines()
    expected = ["refs/heads/main commit "] + [f"{r['tag']} tag {r['commit_id']}" for r in GROUND_TRUTH["revisions"]]
    assert sorted(refs) == sorted(expected)
    assert _read_git(root, "symbolic-ref", "HEAD").strip() == "refs/heads/main"
    assert _read_git(root, "rev-parse", "--is-bare-repository").strip() == "false"
    for rev in GROUND_TRUTH["revisions"]:
        commit = rev["commit_id"]
        assert _read_git(root, "rev-parse", f"{rev['tag']}^{{commit}}").strip() == commit
        assert _read_git(root, "rev-parse", f"{commit}^{{tree}}").strip() == rev["tree_id"]
        header = _read_git(root, "cat-file", "commit", commit)
        assert "author PaperTrail Fixture <fixture@papertrail.invalid>" in header
        parents = [line.split()[1] for line in header.splitlines() if line.startswith("parent ")]
        parent = next((r["commit_id"] for r in GROUND_TRUTH["revisions"] if r["key"] == rev["parent"]), None)
        assert parents == ([parent] if parent else [])
        tag = _read_git(root, "cat-file", "tag", rev["tag_object_id"])
        assert tag.startswith(f"object {commit}\ntype commit\ntag {rev['tag'].removeprefix('refs/tags/')}\n")


def test_independent_porcelain_rebuild_yields_the_same_commit_ids(tmp_path: Path) -> None:
    """Rebuild every revision with ordinary `git commit`/`git tag -a` and compare the IDs."""
    root = private_dir(tmp_path / "porcelain")
    files = papertrail.revision_files()

    def porcelain(*args: str, epoch: int = 0) -> str:
        date = f"@{epoch} +0000"
        env = {"PATH": "/usr/bin:/bin", "HOME": "/var/empty", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
               "GIT_AUTHOR_NAME": "PaperTrail Fixture", "GIT_AUTHOR_EMAIL": "fixture@papertrail.invalid",
               "GIT_COMMITTER_NAME": "PaperTrail Fixture", "GIT_COMMITTER_EMAIL": "fixture@papertrail.invalid",
               "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date}
        proc = subprocess.run([git_binary().real_path, *args], cwd=root, env=env, capture_output=True,
                              check=False, timeout=60)
        assert proc.returncode == 0, proc.stderr
        return proc.stdout.decode().strip()

    porcelain("init", "-q", "--object-format=sha1", "-b", "main")
    commits: dict[str, str] = {}
    for spec in papertrail.REVISIONS:
        if spec.parent is not None:
            porcelain("checkout", "-q", "--detach", commits[spec.parent])
        for rel, content in files[spec.key].items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_bytes(content)
        porcelain("add", "--", *files[spec.key])
        (tmp_path / "msg").write_text(spec.message)
        porcelain("commit", "-q", "--cleanup=verbatim", "-F", str(tmp_path / "msg"), epoch=spec.epoch_seconds)
        commits[spec.key] = porcelain("rev-parse", "HEAD")
        (tmp_path / "tagmsg").write_text(spec.tag_message)
        porcelain("tag", "-a", "--cleanup=verbatim", "-F", str(tmp_path / "tagmsg"), spec.tag, commits[spec.key],
                  epoch=spec.epoch_seconds)
        assert porcelain("rev-parse", f"refs/tags/{spec.tag}") == next(
            r["tag_object_id"] for r in GROUND_TRUTH["revisions"] if r["key"] == spec.key)
    assert commits == {r["key"]: r["commit_id"] for r in GROUND_TRUTH["revisions"]}


# ------------------------------------------------------------ fixture data across revisions


def test_only_authz_differs_and_every_authz_is_distinct() -> None:
    files = papertrail.revision_files()
    assert all(set(f) == set(papertrail.BASE_FILES) | {papertrail.VARYING_FILE} for f in files.values())
    for rel in papertrail.BASE_FILES:
        assert len({files[k][rel] for k in KEYS}) == 1, rel
    assert len({files[k][papertrail.VARYING_FILE] for k in KEYS}) == 4


def test_tree_entries_identical_except_authz(generated: papertrail.GeneratedRepository) -> None:
    listings = {r["key"]: dict(line.split("\t")[::-1] for line in _read_git(
        generated.root, "ls-tree", "-r", r["commit_id"]).splitlines()) for r in GROUND_TRUTH["revisions"]}
    paths = {frozenset(v) for v in listings.values()}
    assert len(paths) == 1
    for path in next(iter(paths)):
        blobs = {listings[k][path] for k in KEYS}
        assert len(blobs) == (4 if path == "papertrail/authz.py" else 1), path
        assert all(entry.startswith("100644 blob ") for entry in (listings[k][path] for k in KEYS))


def test_declared_hashes_match_template_bytes() -> None:
    target = GROUND_TRUTH["target"]
    fixture_bytes = _files("vulnerable")[target["fixture_file"]]
    assert target["fixture_sha256"] == "sha256:" + hashlib.sha256(fixture_bytes).hexdigest()
    for rev in GROUND_TRUTH["revisions"]:
        assert rev["authz_sha256"] == "sha256:" + hashlib.sha256(_files(rev["key"])["papertrail/authz.py"]).hexdigest()


def test_fixture_data_is_synthetic_consistent_and_unique() -> None:
    assert FIXTURE_DATA["fixture_contract"] == GROUND_TRUTH["target"]["fixture_contract"] == "synthetic-documents-v1"
    assert FIXTURE_DATA["synthetic"] is True
    tokens = [u["token"] for u in FIXTURE_DATA["users"]]
    assert len(set(tokens)) == len(tokens) == len(USERS) == 3
    assert all(t.startswith("pt-synthetic-") for t in tokens)
    roles = {u["user_id"]: u["role"] for u in FIXTURE_DATA["users"]}
    assert roles == {"u-alice": "member", "u-bob": "member", "u-carol": "auditor"}
    assert {d["document_id"]: (d["owner_id"], d["reader_roles"]) for d in FIXTURE_DATA["documents"]} == {
        "doc-alice-private": ("u-alice", ["auditor"]), "doc-bob-private": ("u-bob", [])}
    raw = json.dumps(FIXTURE_DATA)
    markers = {c["protected_marker"] for c in CHECKS.values() if c["protected_marker"]}
    assert len(markers) == 2
    for marker in markers:
        assert raw.count(marker) == 1
        assert sum(marker in d["content"] for d in FIXTURE_DATA["documents"]) == 1
    forged = CALLERS["forged-token"]["presented_token"]
    assert forged not in tokens and forged not in raw
    for caller in CALLERS.values():
        assert (caller["user_id"] in USERS) == (caller["authorization"] == "fixture-bearer")


def test_tokens_and_markers_live_only_in_the_fixture_file() -> None:
    secrets = [u["token"] for u in FIXTURE_DATA["users"]] + [c["protected_marker"] for c in CHECKS.values()
                                                            if c["protected_marker"]]
    for key in KEYS:
        for rel, content in _files(key).items():
            if rel != GROUND_TRUTH["target"]["fixture_file"]:
                assert not any(s.encode() in content for s in secrets), rel


# ------------------------------------------------------------ PP-005 integration


def test_pp005_registers_and_snapshots_every_revision(tmp_path: Path,
                                                       generated: papertrail.GeneratedRepository) -> None:
    before = fingerprint(generated.root)
    repo = register_repository(generated.root, git_binary())
    assert repo.object_format.value == "sha1"
    dest = private_dir(tmp_path / "snapshots")
    validator = _validator("source-manifest")
    for rev in GROUND_TRUTH["revisions"]:
        result = create_snapshot(repo, rev["tag"], SCOPE, dest)
        manifest = result.manifest
        assert list(validator.iter_errors(manifest)) == []
        assert (manifest["commit_id"], manifest["tree_id"], manifest["requested_revision"]) == (
            rev["commit_id"], rev["tree_id"], rev["tag"])
        assert [f["path"] for f in manifest["files"]] == [
            "fixtures/synthetic/synthetic-documents-v1.json", "papertrail/__init__.py", "papertrail/app.py",
            "papertrail/authz.py", "papertrail/fixtures.py"]
        assert manifest["excluded"] == [{"path": "README.md", "reason": "OUTSIDE_SOURCE_SCOPE", "mode": "100644"}]
        assert manifest["complete_commit"] is False and manifest["uncommitted_changes_included"] is False
        for rel, content in _files(rev["key"]).items():
            if rel != "README.md":
                assert (result.source_dir / rel).read_bytes() == content
        assert not (result.source_dir / ".git").exists()
        by_commit = create_snapshot(repo, rev["commit_id"], SCOPE, dest)
        assert {k: v for k, v in by_commit.manifest.items() if k != "requested_revision"} == {
            k: v for k, v in manifest.items() if k != "requested_revision"}
    assert fingerprint(generated.root) == before


def test_snapshot_manifests_are_deterministic_across_generations(tmp_path: Path,
                                                                  generated: papertrail.GeneratedRepository) -> None:
    other = papertrail.generate_reference_repository(private_dir(tmp_path / "g") / "repo")
    dest = private_dir(tmp_path / "s")
    for rev in GROUND_TRUTH["revisions"]:
        a = create_snapshot(register_repository(generated.root, git_binary()), rev["tag"], SCOPE, dest)
        b = create_snapshot(register_repository(other.root, git_binary()), rev["tag"], SCOPE, dest)
        assert canonical_json(a.manifest) == canonical_json(b.manifest)
        assert a.manifest_sha256 == b.manifest_sha256


def test_resolve_refuses_ambiguous_short_names_of_the_tags(generated: papertrail.GeneratedRepository) -> None:
    repo = register_repository(generated.root, git_binary())
    for short in ("authz-r1-vulnerable", "main", "HEAD", "refs/tags/authz-r3-correct^{tree}"):
        with pytest.raises(SourceError):
            resolve_revision(repo, short)


def test_source_scope_keeps_fixture_and_excludes_no_required_path() -> None:
    assert not any(is_secret_path(rel) for rel in _files("vulnerable"))
    profile_path = ROOT / "schemas/examples/valid/execution-profile.v1.1--papertrail-reference.json"
    profile = json.loads(profile_path.read_text())
    target = GROUND_TRUTH["target"]
    assert profile["source_scope"] == target["source_scope"]
    assert (profile["asgi_app"], profile["fixture_contract"], profile["network_policy"], profile["adapter"]) == (
        target["asgi_app"], target["fixture_contract"], target["network_policy"], target["adapter"])


# ------------------------------------------------------------ no original repository is touched


def test_generation_writes_only_inside_the_new_destination(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dest = private_dir(tmp_path / "w") / "repo"
    templates_before = fingerprint(EXAMPLE)
    project_git_before = fingerprint(ROOT / ".git") if (ROOT / ".git").is_dir() else {}
    writes: list[str] = []
    real_open, real_mkdir = os.open, os.mkdir

    def tracking_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT):
            writes.append(str(path))
        return real_open(path, flags, *args, **kwargs)

    def tracking_mkdir(path: Any, *args: Any, **kwargs: Any) -> None:
        writes.append(str(path))
        real_mkdir(path, *args, **kwargs)

    def no_process(*_a: Any, **_k: Any) -> None:
        raise AssertionError("the generator must not start processes")

    monkeypatch.setattr(os, "open", tracking_open)
    monkeypatch.setattr(os, "mkdir", tracking_mkdir)
    monkeypatch.setattr(subprocess, "Popen", no_process)
    monkeypatch.setattr(os, "system", no_process)
    papertrail.generate_reference_repository(dest)
    monkeypatch.undo()
    assert writes and all(Path(w) == dest or Path(w).is_relative_to(dest) for w in writes)
    assert fingerprint(EXAMPLE) == templates_before
    if project_git_before:
        assert fingerprint(ROOT / ".git") == project_git_before


def test_reference_package_never_imports_process_or_target_code() -> None:
    for path in (ROOT / "src" / "patchproof" / "reference").glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import) or (isinstance(node, ast.ImportFrom) and node.level == 0):
                # Relative imports (level > 0) stay inside patchproof.reference itself.
                module = getattr(node, "module", None) or ""
                names = {a.name.split(".")[0] for a in node.names} | {module.split(".")[0]}
                assert not names & {"subprocess", "papertrail", "importlib", "runpy", "pty", "multiprocessing"}, path
            if isinstance(node, ast.Call):
                assert ast.unparse(node.func) not in ("eval", "exec", "compile", "__import__", "os.system",
                                                      "os.popen"), path


def test_papertrail_is_never_imported_into_the_test_process() -> None:
    assert not any(name == "papertrail" or name.startswith("papertrail.") for name in sys.modules)


# ------------------------------------------------------------ destination safety


def _refused(dest: Path, match: str, **kwargs: Any) -> None:
    before = os.path.lexists(dest)
    with pytest.raises(FixtureGenerationError, match=match):
        papertrail.generate_reference_repository(dest, **kwargs)
    assert os.path.lexists(dest) == before


def test_destination_must_be_absolute_canonical_and_new(tmp_path: Path) -> None:
    base = private_dir(tmp_path / "d")
    _refused(Path("relative/repo"), "absolute")
    _refused(Path(str(base) + "/x/../repo"), "canonical")
    (base / "link").symlink_to(base)
    _refused(base / "link" / "repo", "canonical")
    (base / "exists").mkdir()
    _refused(base / "exists", "already exists")
    (base / "file").write_text("x")
    _refused(base / "file", "already exists")
    _refused(base / "missing" / "repo", "parent")


def test_destination_cannot_be_home_its_ancestors_or_the_project(tmp_path: Path) -> None:
    # An existing home directory is already refused as "already exists"; a home that is not
    # created yet shows the dedicated rule for the home directory and its ancestors.
    parent = private_dir(tmp_path / "h")
    _refused(parent / "home", "home directory", home=parent / "home")
    _refused(parent / "anc", "home directory", home=parent / "anc" / "user")
    _refused(parent, "already exists", home=parent / "user")
    project = private_dir(tmp_path / "proj")
    _refused(project / "repo", "PatchProof source repository", project_root=project)
    _refused(ROOT / "papertrail-out", "PatchProof source repository")
    _refused(ROOT / "examples" / "papertrail" / "out", "PatchProof source repository")


def test_destination_inside_another_repository_is_refused(tmp_path: Path) -> None:
    outer = private_dir(tmp_path / "outer")
    (outer / ".git").mkdir()
    private_dir(outer / "nested")
    _refused(outer / "nested" / "repo", "inside another Git repository")
    # The retained home repository is the one documented exception; a fake home shows the rule.
    home = private_dir(tmp_path / "home2")
    (home / ".git").mkdir()
    papertrail.validate_destination(private_dir(home / "work") / "repo", home=home)


def test_destination_parent_must_be_owned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    base = private_dir(tmp_path / "o")
    monkeypatch.setattr(os, "getuid", lambda: os.lstat(base).st_uid + 1)
    _refused(base / "repo", "owned by the current user")


def test_failure_after_creation_removes_the_partial_repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dest = private_dir(tmp_path / "f") / "repo"

    def broken(self: gitobjects.LooseObjectRepository) -> int:
        raise FixtureGenerationError("simulated verification failure")

    monkeypatch.setattr(gitobjects.LooseObjectRepository, "verify", broken)
    with pytest.raises(FixtureGenerationError, match="simulated"):
        papertrail.generate_reference_repository(dest)
    assert not os.path.lexists(dest)


def test_corrupted_object_is_detected_by_verify(tmp_path: Path) -> None:
    root = private_dir(tmp_path / "c")
    repo = gitobjects.LooseObjectRepository(root)
    repo.initialize("refs/heads/main")
    oid = repo.put("blob", b"synthetic\n")
    path = root / ".git" / "objects" / oid[:2] / oid[2:]
    os.chmod(path, 0o644)
    path.write_bytes(zlib.compress(b"blob 9\0tampered!"))
    with pytest.raises(FixtureGenerationError, match="did not verify"):
        repo.verify()


def test_non_canonical_object_header_is_detected_by_verify(tmp_path: Path) -> None:
    """Same payload and hash, but a zero-padded size in the stored header: only the byte comparison sees it."""
    root = private_dir(tmp_path / "n")
    repo = gitobjects.LooseObjectRepository(root)
    repo.initialize("refs/heads/main")
    oid = repo.put("blob", b"synthetic\n")
    path = root / ".git" / "objects" / oid[:2] / oid[2:]
    os.chmod(path, 0o644)
    path.write_bytes(zlib.compress(b"blob 010\0synthetic\n"))
    assert gitobjects.object_id("blob", b"synthetic\n") == oid
    with pytest.raises(FixtureGenerationError, match="did not verify"):
        repo.verify()


# ------------------------------------------------------------ template safety


def _copy_templates(tmp_path: Path) -> Path:
    dst = private_dir(tmp_path / "templates")
    for rel in [f"template/{r}" for r in papertrail.BASE_FILES] + [f"revisions/{k}/authz.py" for k in KEYS]:
        (dst / rel).parent.mkdir(parents=True, exist_ok=True)
        (dst / rel).write_bytes((EXAMPLE / rel).read_bytes())
    return dst


def test_template_symlinks_and_oversized_files_are_refused(tmp_path: Path) -> None:
    templates = _copy_templates(tmp_path)
    assert papertrail.revision_files(templates) == papertrail.revision_files()
    app = templates / "template" / "papertrail" / "app.py"
    app.unlink()
    app.symlink_to("/etc/hosts")
    with pytest.raises(FixtureGenerationError, match="symlink"):
        papertrail.revision_files(templates)
    app.unlink()
    app.write_bytes(b"#" * (papertrail.MAX_TEMPLATE_BYTES + 1))
    with pytest.raises(FixtureGenerationError, match="size limit"):
        papertrail.revision_files(templates)
    app.unlink()
    with pytest.raises(FileNotFoundError):
        papertrail.revision_files(templates)
    with pytest.raises(FixtureGenerationError, match="canonical"):
        papertrail.revision_files(Path(str(templates) + "/../templates"))


def test_changed_template_changes_the_commit_ids(tmp_path: Path) -> None:
    templates = _copy_templates(tmp_path)
    authz = templates / "revisions" / "correct" / "authz.py"
    authz.write_bytes(authz.read_bytes() + b"\n")
    record = papertrail.generate_reference_repository(private_dir(tmp_path / "x") / "repo",
                                                      templates=templates).as_record()
    by_key = {r["key"]: r["commit_id"] for r in record["revisions"]}
    declared = {r["key"]: r["commit_id"] for r in GROUND_TRUTH["revisions"]}
    assert by_key["correct"] != declared["correct"]
    assert {k: v for k, v in by_key.items() if k != "correct"} == {k: v for k, v in declared.items() if k != "correct"}


# ------------------------------------------------------------ Git object encoding


def test_object_ids_match_git_hash_object(tmp_path: Path) -> None:
    root = private_dir(tmp_path / "h")
    git(root, "init", "-q", "--object-format=sha1")
    for content in (b"", b"synthetic\n", bytes(range(256))):
        stdout = git(root, "hash-object", "--stdin", stdin=content).decode().strip()
        assert gitobjects.object_id("blob", content) == stdout
    blob = gitobjects.object_id("blob", b"x")
    entries = {"a": (gitobjects.TREE_MODE, gitobjects.object_id("tree", b"")), "a.b": (gitobjects.FILE_MODE, blob),
               "a-b": (gitobjects.FILE_MODE, blob), "b": (gitobjects.FILE_MODE, blob)}
    payload = gitobjects.tree_payload(entries)
    mktree_input = "".join(f"{m} {'tree' if m == gitobjects.TREE_MODE else 'blob'} {o}\t{n}\n"
                           for n, (m, o) in entries.items()).encode()
    expected = git(root, "mktree", "--missing", stdin=mktree_input).decode().strip()
    assert gitobjects.object_id("tree", payload) == expected


@pytest.mark.parametrize("bad", [
    lambda: gitobjects.tree_payload({"../x": (gitobjects.FILE_MODE, "0" * 40)}),
    lambda: gitobjects.tree_payload({".git": (gitobjects.FILE_MODE, "0" * 40)}),
    lambda: gitobjects.tree_payload({"x": ("120000", "0" * 40)}),
    lambda: gitobjects.tree_payload({"x": (gitobjects.FILE_MODE, "0" * 39)}),
    lambda: gitobjects.commit_payload("0" * 40, (), Signature("A <a@b.invalid>", 1), Signature("A <a@b.invalid>", 1),
                                      "no newline"),
    lambda: gitobjects.commit_payload("0" * 40, (), Signature("A <a@b.invalid>", 1), Signature("A <a@b.invalid>", 1),
                                      "café\n"),
    lambda: gitobjects.tag_payload("0" * 40, "--force", Signature("A <a@b.invalid>", 1), "m\n"),
    lambda: gitobjects.tag_payload("0" * 40, "x..y", Signature("A <a@b.invalid>", 1), "m\n"),
    lambda: Signature("A <a@b.invalid>\nparent x", 1),
    lambda: Signature("A <a@b.invalid>", 0),
])
def test_encoders_refuse_unsafe_input(bad: Callable[[], object]) -> None:
    with pytest.raises(FixtureGenerationError):
        bad()


def test_writer_refuses_unsafe_refs_and_existing_files(tmp_path: Path) -> None:
    root = private_dir(tmp_path / "r")
    repo = gitobjects.LooseObjectRepository(root)
    with pytest.raises(FixtureGenerationError):
        repo.initialize("refs/tags/main")
    repo.initialize("refs/heads/main")
    oid = repo.put("blob", b"a")
    for ref in ("HEAD", "refs/heads/../../config", "refs/remotes/x", "refs/heads/Main"):
        with pytest.raises(FixtureGenerationError):
            repo.set_ref(ref, oid)
    repo.set_ref("refs/heads/main", oid)
    with pytest.raises(FileExistsError):
        repo.set_ref("refs/heads/main", oid)
    with pytest.raises(FileExistsError):
        gitobjects.LooseObjectRepository(root).initialize("refs/heads/main")


# ------------------------------------------------------------ static ASGI structure


def _module(rel: str, rev: str = "vulnerable") -> ast.Module:
    return ast.parse(_files(rev)[rel].decode(), filename=rel)


def test_every_target_module_parses_and_imports_only_reviewed_modules() -> None:
    allowed = {"__future__", "hmac", "json", "dataclasses", "pathlib", "collections.abc", "typing",
               "papertrail", "papertrail.fixtures"}
    for key in KEYS:
        for rel, content in _files(key).items():
            if not rel.endswith(".py"):
                continue
            tree = ast.parse(content.decode(), filename=rel)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    assert {a.name for a in node.names} <= allowed, (key, rel)
                if isinstance(node, ast.ImportFrom):
                    assert node.module in allowed and node.level == 0, (key, rel)
                if isinstance(node, ast.Call):
                    assert ast.unparse(node.func) not in ("eval", "exec", "compile", "__import__", "open"), (key, rel)


def test_asgi_entry_point_matches_the_profile_grammar_and_source() -> None:
    module, _, attr = GROUND_TRUTH["target"]["asgi_app"].partition(":")
    rel = module.replace(".", "/") + ".py"
    assert rel == "papertrail/app.py" and rel.split("/")[0] in GROUND_TRUTH["target"]["source_scope"]["include"]
    apps = [n for n in _module(rel).body if isinstance(n, ast.AsyncFunctionDef) and n.name == attr]
    assert len(apps) == 1 and [a.arg for a in apps[0].args.args] == ["scope", "receive", "send"]
    source = _files("vulnerable")[rel].decode()
    for needle in ('"lifespan.startup.complete"', '"lifespan.shutdown.complete"', '"http.response.start"',
                   '"http.response.body"', '(b"cache-control", b"no-store")'):
        assert needle in source


def _route() -> ast.FunctionDef:
    return next(n for n in _module("papertrail/app.py").body if isinstance(n, ast.FunctionDef) and n.name == "route")


def _branch(test_source: str) -> list[ast.stmt]:
    return next(n.body for n in _route().body if isinstance(n, ast.If) and ast.unparse(n.test) == test_source)


def _status(stmt: ast.stmt) -> int:
    assert isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Tuple)
    status = stmt.value.elts[0]
    assert isinstance(status, ast.Constant) and isinstance(status.value, int)
    return status.value


def test_route_authenticates_before_any_document_lookup_or_authorization() -> None:
    body = _route().body
    order = [ast.unparse(n.test) if isinstance(n, ast.If) else ast.unparse(n) for n in body]
    assert order[:4] == ["method != 'GET'", "path == '/health'", "user = authenticate(FIXTURE, authorization)",
                         "path == '/me'"]
    for branch in ("path == '/me'", "path.startswith(DOCUMENT_PREFIX)"):
        first = _branch(branch)[0]
        assert isinstance(first, ast.If) and ast.unparse(first.test) == "user is None"
        assert _status(first.body[0]) == 401
    docs = _branch("path.startswith(DOCUMENT_PREFIX)")
    assert ast.unparse(docs[1]) == "document = FIXTURE.document(path.removeprefix(DOCUMENT_PREFIX))"
    deny = docs[2]
    assert isinstance(deny, ast.If)
    assert ast.unparse(deny.test) == "document is None or not authz.can_read_document(user, document)"
    assert _status(deny.body[0]) == 404
    ok = docs[3]
    assert _status(ok) == 200
    assert isinstance(ok, ast.Return) and isinstance(ok.value, ast.Tuple) and isinstance(ok.value.elts[1], ast.Dict)
    keys = [k.value for k in ok.value.elts[1].keys if isinstance(k, ast.Constant)]
    assert keys == ["document_id", "owner_id", "title", "content"]
    calls = [n for n in ast.walk(_module("papertrail/app.py")) if isinstance(n, ast.Call)
             and ast.unparse(n.func) == "authz.can_read_document"]
    assert len(calls) == 1


def test_authentication_uses_constant_time_exact_token_match() -> None:
    func = next(n for n in _module("papertrail/fixtures.py").body
                if isinstance(n, ast.FunctionDef) and n.name == "authenticate")
    source = ast.unparse(func)
    assert "hmac.compare_digest(presented, user.token.encode('ascii'))" in source
    assert "authorization is None or not authorization.startswith(BEARER_PREFIX)" in source
    returns = [ast.unparse(n.value) for n in ast.walk(func) if isinstance(n, ast.Return) and n.value is not None]
    assert sorted(returns) == ["None", "None", "match"]
    assert ast.unparse(func.body[-1]) == "return match"


# ------------------------------------------------------------ authorization semantics per revision


def test_interpreter_refuses_constructs_outside_its_language() -> None:
    for source in ("import os\ndef can_read_document(user, document):\n    return True\n",
                   "def can_read_document(user, document):\n    return __import__('os') is None\n",
                   "def can_read_document(user, document):\n    return user.token == 'x'\n",
                   "def can_read_document(user, document):\n    if user:\n        pass\n    return True\n",
                   "def can_read_document(user, document):\n    if user is None:\n        return False\n",
                   "def other(user, document):\n    return True\n"):
        with pytest.raises(Unsupported):
            load_policy(source)(USERS["u-alice"], DOCUMENTS["doc-alice-private"])


def _matrix(rev: str) -> dict[tuple[str, str], bool]:
    decide = policy(rev)
    return {(u, d): decide(USERS[u], DOCUMENTS[d]) for u in USERS for d in DOCUMENTS}


def test_vulnerable_allows_every_authenticated_read() -> None:
    assert all(_matrix("vulnerable").values())
    assert policy("vulnerable")(None, DOCUMENTS["doc-alice-private"]) is False


def test_inadequate_changes_code_but_not_the_object_level_decision() -> None:
    assert _matrix("inadequate") == _matrix("vulnerable")
    inadequate = _module("papertrail/authz.py", "inadequate")
    vulnerable = _module("papertrail/authz.py", "vulnerable")
    assert ast.dump(inadequate) != ast.dump(vulnerable)
    names = {ast.unparse(n) for n in ast.walk(inadequate) if isinstance(n, ast.Attribute)}
    assert {"user.user_id", "user.role"} <= names and not any(n.startswith("document.") for n in names)
    # The added role check is real: an account outside READ_ROLES is refused by this revision only.
    guest = {"user_id": "u-guest", "role": "guest"}
    assert policy("inadequate")(guest, DOCUMENTS["doc-alice-private"]) is False
    assert policy("vulnerable")(guest, DOCUMENTS["doc-alice-private"]) is True


def test_correct_enforces_owner_or_granted_role_only() -> None:
    assert _matrix("correct") == {
        ("u-alice", "doc-alice-private"): True, ("u-alice", "doc-bob-private"): False,
        ("u-bob", "doc-alice-private"): False, ("u-bob", "doc-bob-private"): True,
        ("u-carol", "doc-alice-private"): True, ("u-carol", "doc-bob-private"): False,
    }
    correct = _module("papertrail/authz.py", "correct")
    names = {ast.unparse(n) for n in ast.walk(correct) if isinstance(n, ast.Attribute)}
    assert {"document.owner_id", "document.reader_roles", "user.user_id", "user.role"} <= names


def test_deny_all_refuses_every_read_including_legitimate_ones() -> None:
    assert not any(_matrix("deny-all").values())


@pytest.mark.parametrize("rev", KEYS)
@pytest.mark.parametrize("check_id", sorted(CHECKS))
def test_declared_expectation_follows_from_source(rev: str, check_id: str) -> None:
    assert CHECKS[check_id]["expected"][rev] == derive_outcome(rev, CHECKS[check_id])


def test_unauthenticated_and_forged_callers_are_secure_on_every_revision() -> None:
    for check in CHECKS.values():
        if check["caller"] in ("anonymous", "forged-token"):
            assert {check["expected"][k]["status"] for k in KEYS} == {401}


def test_every_legitimate_behavior_has_a_positive_control() -> None:
    functional = [c for c in CHECKS.values() if c["kind"] == "functional"]
    covered = {(c["caller"], c["path"]) for c in functional}
    for (user, doc), allowed in _matrix("correct").items():
        caller = next(k for k, v in CALLERS.items() if v["user_id"] == user)
        assert ((caller, f"/documents/{doc}") in covered) == allowed
    for check in functional:
        assert all(check["expected"][k]["semantic"] == "PASS" for k in ("vulnerable", "inadequate", "correct"))


# ------------------------------------------------------------ comparisons through the PP-004 engine


def _pack_tests() -> list[dict[str, str]]:
    tests = []
    for i, check in enumerate(sorted(CHECKS.values(), key=lambda c: c["id"])):
        baseline = check["expected"]["vulnerable"]["semantic"]
        tests.append({"id": check["id"], "nodeid": f"tests/test_documents.py::test_case_{i:02d}", "kind": check["kind"],
                      "baseline_expected": baseline,
                      "candidate_expected": "SECURE" if check["kind"] == "security" else "PASS"})
    return tests


@pytest.mark.parametrize("comparison", GROUND_TRUTH["comparisons"], ids=lambda c: c["candidate"])
def test_declared_comparison_verdicts_follow_from_the_accepted_engine(comparison: dict[str, str]) -> None:
    """Feed the declared outcomes as trusted, complete observations; the engine must agree."""
    tests = _pack_tests()
    data = verified_input(tests=copy.deepcopy(tests))
    for obs in data["observations"]:
        rev = comparison["baseline"] if obs["side"] == "baseline" else comparison["candidate"]
        obs["semantic_outcome"] = CHECKS[obs["test_id"]]["expected"][rev]["semantic"]
    result = run_verdict(resync(data))
    assert result["verdict"] == comparison["expected_verdict"]


def test_comparisons_cover_the_section_17_2_matrix() -> None:
    assert [(c["candidate"], c["expected_verdict"]) for c in GROUND_TRUTH["comparisons"]] == [
        ("vulnerable", "NOT_FIXED"), ("inadequate", "NOT_FIXED"), ("correct", "VERIFIED_FOR_CASES"),
        ("deny-all", "REGRESSION_DETECTED")]


# ------------------------------------------------------------ ground-truth record and documentation


def _validator(name: str) -> Draft202012Validator:
    schemas = [json.loads(p.read_text()) for p in (ROOT / "schemas").glob("*.schema.json")]
    registry: Registry = Registry().with_resources((s["$id"], Resource.from_contents(s)) for s in schemas)
    return Draft202012Validator(json.loads((ROOT / "schemas" / f"{name}.schema.json").read_text()), registry=registry)


def test_ground_truth_validates_and_matches_the_schema_example() -> None:
    assert list(_validator("reference-fixture").iter_errors(GROUND_TRUTH)) == []
    example = ROOT / "schemas" / "examples" / "valid" / "reference-fixture--papertrail-authz.json"
    assert example.read_bytes() == GROUND_TRUTH_PATH.read_bytes()


def test_ground_truth_claims_no_approval_or_observation() -> None:
    assert GROUND_TRUTH["approval_status"] == "NOT_APPROVED"
    assert GROUND_TRUTH["declared_expectations_only"] is True
    assert GROUND_TRUTH["target"]["server"]["version"] == "UNRESOLVED"
    assert {"target_image_id", "verifier_image_id"} <= set(GROUND_TRUTH["target"]["unresolved_bindings"])
    assert "has not been executed" in GROUND_TRUTH["limitations"][0]


def test_documentation_states_the_recorded_identities_and_expectations() -> None:
    text = DOC.read_text()
    for rev in GROUND_TRUTH["revisions"]:
        for value in (rev["tag"], rev["commit_id"], rev["tree_id"], rev["tag_object_id"]):
            assert value in text, value
    short = {"VIOLATION_CONFIRMED": "VIOLATION", "SECURE": "SECURE", "PASS": "PASS", "FAIL": "FAIL"}
    for check in CHECKS.values():
        cells = " | ".join(f"{short[check['expected'][k]['semantic']]} {check['expected'][k]['status']}"
                           for k in KEYS)
        row = f"| {check['id']} | {check['kind']} | {check['caller']} | `{check['path']}` | {cells} |"
        assert row in text, check["id"]
    for comparison in GROUND_TRUTH["comparisons"]:
        assert f"| `{comparison['candidate']}` | `{comparison['expected_verdict']}` |" in text
    assert "**Nothing here has been executed.**" in text


# ------------------------------------------------------------ command-line entry point


def test_module_entry_point(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_main([]) == 2
    dest = private_dir(tmp_path / "cli") / "repo"
    assert cli_main([str(dest)]) == 0
    record = json.loads(capsys.readouterr().out)
    assert [r["commit_id"] for r in record["revisions"]] == [r["commit_id"] for r in GROUND_TRUTH["revisions"]]
    assert str(tmp_path) not in json.dumps(record)
    assert cli_main([str(dest)]) == 1
    assert "already exists" in capsys.readouterr().err
