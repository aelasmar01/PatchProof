"""PP-005: repository registration, revision resolution, and read-only source snapshots.

Integration tests against synthetic repositories that the real, reviewed Git executable
creates under tmp_path. Every snapshot test also asserts that the original repository's
complete filesystem fingerprint (worktree and .git, including mtimes) is unchanged.
"""

from __future__ import annotations

import json
import os
import unicodedata
from pathlib import Path
from typing import Any

import pytest
from _git_fixtures import Repo, fingerprint, git_binary, make_repo, private_dir
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from patchproof.git import snapshot as snap
from patchproof.git.command import ObjectFormat
from patchproof.git.errors import Reason, SourceError
from patchproof.git.paths import SourceScope
from patchproof.git.repository import RegisteredRepository, register_repository, resolve_revision
from patchproof.git.snapshot import SnapshotLimits, create_snapshot

ROOT = Path(__file__).resolve().parents[2]
APP_FILES = {
    "app/__init__.py": b"",
    "app/main.py": b"print('synthetic')\n",
    "app/data/fixture.json": b'{"owner": "alice"}\n',
    "tests/test_app.py": b"def test_x():\n    pass\n",
    "README.md": b"# synthetic\n",
}
SCOPE = SourceScope.of(["app"])


def _schema_validator() -> Draft202012Validator:
    docs = [json.loads(p.read_text()) for p in (ROOT / "schemas").glob("*.schema.json")]
    registry: Registry = Registry().with_resources((d["$id"], Resource.from_contents(d)) for d in docs)
    return Draft202012Validator(json.loads((ROOT / "schemas" / "source-manifest.schema.json").read_text()),
                                registry=registry)


MANIFEST_VALIDATOR = _schema_validator()


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    return Path(os.path.realpath(tmp_path))


@pytest.fixture
def dest(workspace: Path) -> Path:
    return private_dir(workspace / "snapshots")


@pytest.fixture
def repo(workspace: Path) -> Repo:
    return make_repo(workspace / "repo", APP_FILES)


@pytest.fixture
def home(workspace: Path) -> Path:
    return private_dir(workspace / "home")


def register(repo: Repo, home: Path) -> RegisteredRepository:
    return register_repository(repo.root, git_binary(), home=home)


@pytest.fixture
def registered(repo: Repo, home: Path) -> RegisteredRepository:
    before = fingerprint(repo.root)
    reg = register(repo, home)
    assert fingerprint(repo.root) == before, "registration changed the repository"
    return reg


def snapshot(reg: RegisteredRepository, revision: str, scope: SourceScope, dest: Path,
             **kwargs: Any) -> snap.SnapshotResult:
    """create_snapshot, asserting the original repository is byte-for-byte unchanged (INV-13)."""
    before = fingerprint(reg.root)
    try:
        return create_snapshot(reg, revision, scope, dest, **kwargs)
    finally:
        assert fingerprint(reg.root) == before, "snapshot creation changed the original repository"


def resolve(reg: RegisteredRepository, revision: str) -> Any:
    before = fingerprint(reg.root)
    try:
        return resolve_revision(reg, revision)
    finally:
        assert fingerprint(reg.root) == before, "revision resolution changed the original repository"


def reason_of(excinfo: pytest.ExceptionInfo[SourceError]) -> Reason:
    return excinfo.value.reason


def assert_nothing_produced(dest: Path) -> None:
    assert list(dest.iterdir()) == [], "a failed snapshot left output behind"


# --- registration ------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", ["sha1", "sha256"])
def test_registers_sha1_and_sha256_repositories_and_records_the_format(workspace: Path, home: Path, fmt: str) -> None:
    repo = make_repo(workspace / f"r-{fmt}", APP_FILES, object_format=fmt)
    before = fingerprint(repo.root)
    reg = register(repo, home)
    assert reg.object_format is ObjectFormat(fmt) and reg.root == repo.root
    assert fingerprint(repo.root) == before


def test_registration_rejects_relative_and_non_canonical_paths(repo: Repo, home: Path, workspace: Path) -> None:
    with pytest.raises(SourceError) as e:
        register_repository("repo", git_binary(), home=home)
    assert reason_of(e) is Reason.PATH_NOT_ABSOLUTE
    link = workspace / "link-to-repo"
    link.symlink_to(repo.root)
    for candidate in (str(link), str(repo.root) + "/", str(repo.root / "app" / ".."), str(repo.root) + "/."):
        with pytest.raises(SourceError) as e:
            register_repository(candidate, git_binary(), home=home)
        assert reason_of(e) is Reason.PATH_NOT_CANONICAL, candidate


def test_registration_rejects_a_subdirectory_instead_of_finding_its_repository(repo: Repo, home: Path) -> None:
    with pytest.raises(SourceError) as e:
        register_repository(repo.root / "app", git_binary(), home=home)
    assert reason_of(e) is Reason.NOT_A_REPOSITORY_ROOT


def test_a_parent_repository_is_never_discovered(workspace: Path) -> None:
    """The ~/.git hazard: a plain project directory below an unrelated parent repository."""
    parent = make_repo(workspace / "fake-home", {"README.md": b"parent\n"})
    child = parent.root / "Desktop" / "project"
    child.mkdir(parents=True)
    (child / "main.py").write_text("x = 1\n")
    before = fingerprint(parent.root)
    with pytest.raises(SourceError) as e:
        register_repository(child, git_binary(), home=parent.root)
    assert reason_of(e) is Reason.NOT_A_REPOSITORY_ROOT
    assert fingerprint(parent.root) == before
    # A real nested repository registers as itself, never as the parent.
    nested = make_repo(parent.root / "Desktop" / "nested", APP_FILES)
    parent_git = fingerprint(parent.root / ".git")
    reg = register_repository(nested.root, git_binary(), home=parent.root)
    assert reg.root == nested.root
    assert fingerprint(parent.root / ".git") == parent_git


def test_the_home_directory_and_its_ancestors_are_refused(workspace: Path) -> None:
    fake_home = make_repo(workspace / "u" / "home", {"README.md": b"x\n"})
    for target in (fake_home.root, fake_home.root.parent):
        with pytest.raises(SourceError) as e:
            register_repository(target, git_binary(), home=fake_home.root)
        assert reason_of(e) in {Reason.HOME_DIRECTORY_REPOSITORY}
    with pytest.raises(SourceError) as e:
        register_repository("/", git_binary(), home=fake_home.root)
    assert reason_of(e) is Reason.HOME_DIRECTORY_REPOSITORY


def test_the_real_home_directory_is_refused_without_touching_it() -> None:
    home = Path(os.path.realpath(Path.home()))
    with pytest.raises(SourceError) as e:
        register_repository(home, git_binary())
    assert reason_of(e) is Reason.HOME_DIRECTORY_REPOSITORY


@pytest.mark.parametrize("layout", ["alternates", "http-alternates", "grafts", "commondir", "gitdir"])
def test_external_object_stores_and_linked_layouts_are_refused(repo: Repo, home: Path, layout: str) -> None:
    rel = {"alternates": "objects/info/alternates", "http-alternates": "objects/info/http-alternates",
           "grafts": "info/grafts", "commondir": "commondir", "gitdir": "gitdir"}[layout]
    target = repo.root / ".git" / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("/nonexistent\n")
    with pytest.raises(SourceError) as e:
        register(repo, home)
    assert reason_of(e) is Reason.UNSUPPORTED_REPOSITORY_LAYOUT


def test_gitdir_files_symlinked_git_and_bare_repositories_are_refused(workspace: Path, home: Path) -> None:
    real = make_repo(workspace / "real", APP_FILES)
    worktree = workspace / "linked"
    real.git("worktree", "add", "-q", str(worktree), "-b", "side")
    with pytest.raises(SourceError) as e:
        register_repository(worktree, git_binary(), home=home)
    assert reason_of(e) is Reason.UNSUPPORTED_REPOSITORY_LAYOUT

    symlinked = workspace / "symlinked"
    symlinked.mkdir()
    (symlinked / ".git").symlink_to(real.root / ".git")
    with pytest.raises(SourceError) as e:
        register_repository(symlinked, git_binary(), home=home)
    assert reason_of(e) is Reason.UNSUPPORTED_REPOSITORY_LAYOUT

    bare = workspace / "bare.git"
    real.git("clone", "-q", "--bare", str(real.root), str(bare))
    with pytest.raises(SourceError) as e:
        register_repository(bare, git_binary(), home=home)
    assert reason_of(e) is Reason.NOT_A_REPOSITORY_ROOT


def test_registration_rejects_files_and_missing_paths(repo: Repo, home: Path) -> None:
    for target in (repo.root / "README.md", repo.root / "missing"):
        with pytest.raises(SourceError) as e:
            register_repository(target, git_binary(), home=home)
        assert reason_of(e) is Reason.NOT_A_DIRECTORY


# --- revision resolution ------------------------------------------------------------------


def test_resolves_full_ids_branches_and_annotated_tags(registered: RegisteredRepository, repo: Repo) -> None:
    head = repo.text("rev-parse", "HEAD")
    tree = repo.text("rev-parse", "HEAD^{tree}")
    repo.git("tag", "-a", "v1", "-m", "annotated")
    repo.git("tag", "light")
    for rev in (head, "refs/heads/main", "refs/tags/v1", "refs/tags/light"):
        resolved = resolve(registered, rev)
        assert (resolved.commit.value, resolved.tree.value, resolved.requested) == (head, tree, rev)


def test_sha256_repository_resolves_64_digit_ids(workspace: Path, home: Path) -> None:
    repo = make_repo(workspace / "r256", APP_FILES, object_format="sha256")
    reg = register(repo, home)
    head = repo.text("rev-parse", "HEAD")
    assert len(head) == 64
    assert resolve(reg, head).commit.value == head
    with pytest.raises(SourceError) as e:
        resolve(reg, head[:40])
    assert reason_of(e) is Reason.ABBREVIATED_OBJECT_ID


@pytest.mark.parametrize("revision", [
    "main", "HEAD", "HEAD~1", "main^", "@{-1}", "@", ":/synthetic", "-n", "--output=/tmp/x", "--all",
    "refs/heads/../x", "refs/heads/main..refs/tags/v1", "refs/heads/.hidden", "refs/heads/x.lock",
    "refs/remotes/origin/main", "refs/heads/-x", "refs/heads/main@{0}", "refs/heads/main^{tree}",
    "refs/heads/a b", "refs/heads/a\nb", "refs/heads/", "refs/", "", " ", "main:README.md",
    "HEAD^{commit}", "FETCH_HEAD", "ORIG_HEAD", "stash", "A" * 40,
])
def test_unsupported_revision_expressions_are_refused(registered: RegisteredRepository, revision: str) -> None:
    with pytest.raises(SourceError) as e:
        resolve(registered, revision)
    assert reason_of(e) is Reason.UNSUPPORTED_REVISION


def test_abbreviated_and_missing_ids_are_refused(registered: RegisteredRepository, repo: Repo) -> None:
    head = repo.text("rev-parse", "HEAD")
    for short in (head[:7], head[:12], head[:39]):
        with pytest.raises(SourceError) as e:
            resolve(registered, short)
        assert reason_of(e) is Reason.ABBREVIATED_OBJECT_ID
    with pytest.raises(SourceError) as e:
        resolve(registered, "0" * 40)
    assert reason_of(e) is Reason.MISSING_OBJECT
    with pytest.raises(SourceError) as e:
        resolve(registered, "refs/heads/does-not-exist")
    assert reason_of(e) is Reason.REF_NOT_FOUND


def test_ids_of_non_commit_objects_are_refused(registered: RegisteredRepository, repo: Repo) -> None:
    blob = repo.text("rev-parse", "HEAD:README.md")
    tree = repo.text("rev-parse", "HEAD^{tree}")
    repo.git("tag", "-a", "v1", "-m", "annotated")
    tag_object = repo.text("rev-parse", "refs/tags/v1")
    for oid in (blob, tree, tag_object):
        with pytest.raises(SourceError) as e:
            resolve(registered, oid)
        assert reason_of(e) is Reason.NOT_A_COMMIT
    blob_tag_target = repo.blob(b"tagged blob\n")
    repo.git("tag", "blobtag", blob_tag_target)
    with pytest.raises(SourceError) as e:
        resolve(registered, "refs/tags/blobtag")
    assert reason_of(e) is Reason.NOT_A_COMMIT


def test_same_short_name_as_branch_and_tag_needs_a_full_ref(registered: RegisteredRepository, repo: Repo) -> None:
    first = repo.text("rev-parse", "HEAD")
    repo.git("tag", "release", first)
    second = repo.commit_files({"app/main.py": b"print('v2')\n"})
    repo.git("branch", "release", second)
    with pytest.raises(SourceError) as e:
        resolve(registered, "release")
    assert reason_of(e) is Reason.UNSUPPORTED_REVISION
    assert resolve(registered, "refs/tags/release").commit.value == first
    assert resolve(registered, "refs/heads/release").commit.value == second


def test_a_branch_named_like_an_object_id_cannot_redirect_a_full_id(registered: RegisteredRepository,
                                                                    repo: Repo) -> None:
    first = repo.text("rev-parse", "HEAD")
    second = repo.commit_files({"app/main.py": b"print('v2')\n"})
    repo.git("update-ref", f"refs/heads/{first}", second)
    assert resolve(registered, first).commit.value == first


# --- snapshots: success, determinism, preservation ------------------------------------------


def test_snapshot_contains_exact_committed_bytes_and_a_valid_manifest(registered: RegisteredRepository,
                                                                      repo: Repo, dest: Path) -> None:
    result = snapshot(registered, "refs/heads/main", SCOPE, dest)
    m = result.manifest
    assert not list(MANIFEST_VALIDATOR.iter_errors(m))
    assert json.loads(result.manifest_path.read_bytes()) == m
    assert m["commit_id"] == repo.text("rev-parse", "HEAD") and m["object_format"] == "sha1"
    assert m["uncommitted_changes_included"] is False and m["complete_commit"] is False
    assert [f["path"] for f in m["files"]] == ["app/__init__.py", "app/data/fixture.json", "app/main.py"]
    assert {e["path"]: e["reason"] for e in m["excluded"]} == {
        "README.md": "OUTSIDE_SOURCE_SCOPE", "tests/test_app.py": "OUTSIDE_SOURCE_SCOPE"}
    for record in m["files"]:
        written = result.source_dir / record["path"]
        assert written.read_bytes() == APP_FILES[record["path"]]
        assert snap.sha256_tag(written.read_bytes()) == record["sha256"]
        assert record["git_object_id"] == repo.text("rev-parse", f"HEAD:{record['path']}")
        assert (written.stat().st_mode & 0o777) == 0o444
    assert m["source_tree_sha256"] == snap.sha256_tag(snap.canonical_json(m["files"]))
    assert (result.source_dir.stat().st_mode & 0o777) == 0o555
    assert not (result.source_dir / ".git").exists()
    assert [p.name for p in dest.iterdir()] == [result.snapshot_dir.name]
    assert str(repo.root) not in result.manifest_path.read_text()


def test_executable_bit_is_preserved_read_only(registered: RegisteredRepository, repo: Repo, dest: Path) -> None:
    (repo.root / "app" / "run.sh").write_text("#!/bin/sh\n")
    os.chmod(repo.root / "app" / "run.sh", 0o755)
    repo.git("add", "app/run.sh")
    repo.git("commit", "-q", "-m", "exec")
    result = snapshot(registered, "refs/heads/main", SCOPE, dest)
    entry = next(f for f in result.manifest["files"] if f["path"] == "app/run.sh")
    assert entry["mode"] == "100755"
    assert (result.source_dir / "app" / "run.sh").stat().st_mode & 0o777 == 0o555


def test_manifest_is_deterministic_and_has_no_local_paths_or_times(registered: RegisteredRepository,
                                                                  dest: Path) -> None:
    a = snapshot(registered, "refs/heads/main", SCOPE, dest)
    b = snapshot(registered, "refs/heads/main", SCOPE, dest)
    assert a.snapshot_dir != b.snapshot_dir
    assert a.manifest_path.read_bytes() == b.manifest_path.read_bytes()
    assert a.manifest_sha256 == b.manifest_sha256 == snap.sha256_tag(a.manifest_path.read_bytes())


def test_profile_hash_binds_scope_and_limits(registered: RegisteredRepository, dest: Path) -> None:
    a = snapshot(registered, "refs/heads/main", SCOPE, dest).manifest
    b = snapshot(registered, "refs/heads/main", SourceScope.of(["app", "tests"]), dest).manifest
    c = snapshot(registered, "refs/heads/main", SCOPE, dest,
                        limits=SnapshotLimits(max_entries=100)).manifest
    hashes = {m["inclusion_profile"]["sha256"] for m in (a, b, c)}
    assert len(hashes) == 3


def test_sha256_repository_snapshot(workspace: Path, home: Path, dest: Path) -> None:
    repo = make_repo(workspace / "r256", APP_FILES, object_format="sha256")
    before = fingerprint(repo.root)
    result = snapshot(register(repo, home), "refs/heads/main", SCOPE, dest)
    assert result.manifest["object_format"] == "sha256" and len(result.manifest["commit_id"]) == 64
    assert all(len(f["git_object_id"]) == 64 for f in result.manifest["files"])
    assert not list(MANIFEST_VALIDATOR.iter_errors(result.manifest))
    assert fingerprint(repo.root) == before


def test_uncommitted_work_is_preserved_and_never_included(registered: RegisteredRepository, repo: Repo,
                                                         dest: Path) -> None:
    (repo.root / "app" / "main.py").write_bytes(b"print('UNCOMMITTED EDIT')\n")
    (repo.root / "app" / "untracked.py").write_bytes(b"untracked\n")
    (repo.root / "app" / "__init__.py").write_bytes(b"staged = True\n")
    repo.git("add", "app/__init__.py")
    status_before = repo.git("status", "--porcelain=v1", "-z")
    before = fingerprint(repo.root)
    result = snapshot(registered, "refs/heads/main", SCOPE, dest)
    assert fingerprint(repo.root) == before
    assert repo.git("status", "--porcelain=v1", "-z") == status_before
    assert (result.source_dir / "app" / "main.py").read_bytes() == APP_FILES["app/main.py"]
    assert (result.source_dir / "app" / "__init__.py").read_bytes() == b""
    assert not (result.source_dir / "app" / "untracked.py").exists()
    assert (repo.root / "app" / "main.py").read_bytes() == b"print('UNCOMMITTED EDIT')\n"


def test_older_commit_by_full_id(registered: RegisteredRepository, repo: Repo, dest: Path) -> None:
    first = repo.text("rev-parse", "HEAD")
    repo.commit_files({"app/main.py": b"print('v2')\n"})
    result = snapshot(registered, first, SCOPE, dest)
    assert result.manifest["commit_id"] == first
    assert (result.source_dir / "app" / "main.py").read_bytes() == APP_FILES["app/main.py"]


# --- snapshots: entry and path rejection --------------------------------------------------


def crafted(repo: Repo, app_entries: list[tuple[str, bytes, str]]) -> None:
    """Point refs/heads/main at a commit whose tree is {app: <crafted tree>, README.md}."""
    readme = repo.blob(b"readme\n")
    app = repo.tree(app_entries)
    repo.commit_tree(repo.tree([("40000", b"app", app), ("100644", b"README.md", readme)]))


def expect_rejected(registered: RegisteredRepository, dest: Path, reasons: set[Reason],
                    scope: SourceScope = SCOPE, **kwargs: Any) -> SourceError:
    with pytest.raises(SourceError) as e:
        snapshot(registered, "refs/heads/main", scope, dest, **kwargs)
    assert reason_of(e) in reasons, e.value
    assert_nothing_produced(dest)
    return e.value


def test_symlink_inside_scope_is_refused(registered: RegisteredRepository, repo: Repo, dest: Path) -> None:
    ok = repo.blob(b"x\n")
    crafted(repo, [("100644", b"main.py", ok), ("120000", b"link", repo.blob(b"/etc/passwd"))])
    expect_rejected(registered, dest, {Reason.SYMLINK_ENTRY})


def test_symlink_outside_scope_is_recorded_as_excluded(registered: RegisteredRepository, repo: Repo,
                                                       dest: Path) -> None:
    ok = repo.blob(b"x\n")
    app = repo.tree([("100644", b"main.py", ok)])
    link = repo.blob(b"../../secret")
    repo.commit_tree(repo.tree([("40000", b"app", app), ("120000", b"docs-link", link)]))
    result = snapshot(registered, "refs/heads/main", SCOPE, dest)
    assert result.manifest["excluded"] == [{"path": "docs-link", "reason": "OUTSIDE_SOURCE_SCOPE", "mode": "120000"}]


def test_gitlink_inside_scope_is_refused(registered: RegisteredRepository, repo: Repo, dest: Path) -> None:
    head = repo.text("rev-parse", "HEAD")
    crafted(repo, [("100644", b"main.py", repo.blob(b"x\n")), ("160000", b"vendored", head)])
    expect_rejected(registered, dest, {Reason.GITLINK_ENTRY})


def test_lfs_pointer_is_refused(registered: RegisteredRepository, repo: Repo, dest: Path) -> None:
    pointer = (b"version https://git-lfs.github.com/spec/v1\n"
               b"oid sha256:" + b"a" * 64 + b"\nsize 12345\n")
    crafted(repo, [("100644", b"model.bin", repo.blob(pointer))])
    expect_rejected(registered, dest, {Reason.LFS_POINTER})


@pytest.mark.parametrize("name", [
    b"..", b".", b".git", b".GIT", b".Git", b".git.", b"git~1", b"a\x1b[31mb", b"tab\tname", b"new\nline",
    b"\xff\xfe", b"zero\xe2\x80\x8bwidth", b".g\xe2\x80\x8cit", b"rtl\xe2\x80\xaeoverride", b"back\\slash",
    b"../escape", b"/absolute", b"a//b",
])
def test_unsafe_names_anywhere_in_the_commit_are_refused(registered: RegisteredRepository, repo: Repo,
                                                         dest: Path, name: bytes) -> None:
    crafted(repo, [("100644", b"main.py", repo.blob(b"x\n")), ("100644", name, repo.blob(b"evil\n"))])
    # Git may itself refuse to walk some crafted trees; either way nothing is produced.
    expect_rejected(registered, dest, {Reason.UNSAFE_PATH, Reason.GIT_COMMAND_FAILED})


def test_unsafe_name_outside_scope_still_refuses_the_snapshot(registered: RegisteredRepository, repo: Repo,
                                                              dest: Path) -> None:
    app = repo.tree([("100644", b"main.py", repo.blob(b"x\n"))])
    evil = repo.tree([("100644", b"\x1b]0;title\x07", repo.blob(b"x\n"))])
    repo.commit_tree(repo.tree([("40000", b"app", app), ("40000", b"docs", evil)]))
    expect_rejected(registered, dest, {Reason.UNSAFE_PATH})


@pytest.mark.parametrize("names", [
    (b"Main.py", b"main.py"),
    ("café.py".encode(), unicodedata.normalize("NFD", "café.py").encode()),
    (b"MAIN.PY", b"main.py"),
])
def test_case_and_normalization_collisions_are_refused(registered: RegisteredRepository, repo: Repo, dest: Path,
                                                       names: tuple[bytes, bytes]) -> None:
    crafted(repo, [("100644", names[0], repo.blob(b"one\n")), ("100644", names[1], repo.blob(b"two\n"))])
    expect_rejected(registered, dest, {Reason.PATH_COLLISION})


def test_file_and_directory_collision_is_refused(registered: RegisteredRepository, repo: Repo, dest: Path) -> None:
    sub = repo.tree([("100644", b"x.py", repo.blob(b"x\n"))])
    crafted(repo, [("100644", b"lib", repo.blob(b"file\n")), ("40000", b"LIB", sub)])
    expect_rejected(registered, dest, {Reason.PATH_COLLISION})


# --- source scope and secret policy -----------------------------------------------------------


def test_secret_files_inside_scope_are_excluded_and_recorded(registered: RegisteredRepository, repo: Repo,
                                                             dest: Path) -> None:
    repo.commit_files({"app/.env": b"TOKEN=synthetic\n", "app/certs/server.pem": b"synthetic\n",
                       "app/.ssh/config": b"Host x\n", "app/settings.py": b"DEBUG = False\n"})
    result = snapshot(registered, "refs/heads/main", SCOPE, dest)
    excluded = {e["path"]: e["reason"] for e in result.manifest["excluded"]}
    for secret in ("app/.env", "app/certs/server.pem", "app/.ssh/config"):
        assert excluded[secret] == "SECRET_FILE_POLICY"
        assert not (result.source_dir / secret).exists()
    assert (result.source_dir / "app" / "settings.py").exists()


@pytest.mark.parametrize("include", [["config/secrets.yaml"], ["app", "deploy/server.key"], ["credentials"],
                                     ["keys/id_rsa"], ["terraform.tfstate"]])
def test_required_paths_matching_the_secret_policy_are_refused(include: list[str]) -> None:
    with pytest.raises(SourceError) as e:
        SourceScope.of(include)
    assert reason_of(e) is Reason.SECRET_PATH_REQUIRED


def test_missing_required_path_is_refused(registered: RegisteredRepository, dest: Path) -> None:
    expect_rejected(registered, dest, {Reason.REQUIRED_PATH_MISSING}, scope=SourceScope.of(["app", "missing"]))


def test_required_path_with_only_secret_files_counts_as_missing(registered: RegisteredRepository, repo: Repo,
                                                                dest: Path) -> None:
    repo.commit_files({"conf/.env": b"X=1\n"})
    expect_rejected(registered, dest, {Reason.REQUIRED_PATH_MISSING}, scope=SourceScope.of(["app", "conf"]))


@pytest.mark.parametrize("include", [[], ["../x"], ["/abs"], ["-rf"], [".git"], ["a/.hidden"], ["app", "app"],
                                     ["a b"], ["x" * 101]])
def test_invalid_source_scopes_are_refused(include: list[str]) -> None:
    with pytest.raises(SourceError) as e:
        SourceScope.of(include)
    assert reason_of(e) is Reason.INVALID_SOURCE_SCOPE


# --- limits --------------------------------------------------------------------------------


def test_default_entry_limit_is_20000(registered: RegisteredRepository, repo: Repo, dest: Path) -> None:
    empty = repo.blob(b"")
    entries = [("100644", f"f{i:05d}.py".encode(), empty) for i in range(20_001)]
    crafted(repo, entries)
    expect_rejected(registered, dest, {Reason.ENTRY_LIMIT})


def test_entry_limit_allows_exactly_the_limit(registered: RegisteredRepository, repo: Repo, dest: Path) -> None:
    empty = repo.blob(b"")
    crafted(repo, [("100644", f"f{i}.py".encode(), empty) for i in range(5)])
    result = snapshot(registered, "refs/heads/main", SCOPE, dest, limits=SnapshotLimits(max_entries=5))
    assert result.manifest["totals"]["file_count"] == 5
    expect_rejected(registered, private_dir(dest.parent / "d2"), {Reason.ENTRY_LIMIT},
                    limits=SnapshotLimits(max_entries=4))


def test_default_per_file_limit_is_10_mib(registered: RegisteredRepository, repo: Repo, dest: Path) -> None:
    crafted(repo, [("100644", b"big.bin", repo.blob(b"\0" * (10 * 1024 * 1024 + 1)))])
    expect_rejected(registered, dest, {Reason.FILE_SIZE_LIMIT})


def test_default_total_limit_is_100_mib_and_checked_before_reading(registered: RegisteredRepository, repo: Repo,
                                                                   dest: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ten = repo.blob(b"\1" * (10 * 1024 * 1024))
    crafted(repo, [("100644", f"part{i}.bin".encode(), ten) for i in range(11)])
    monkeypatch.setattr(snap, "parse_cat_file_batch", lambda *a: pytest.fail("blobs were read before the limit"))
    expect_rejected(registered, dest, {Reason.TOTAL_SIZE_LIMIT})


def test_tree_listing_bound(registered: RegisteredRepository, repo: Repo, dest: Path) -> None:
    empty = repo.blob(b"")
    crafted(repo, [("100644", f"f{i}".encode(), empty) for i in range(10)])
    expect_rejected(registered, dest, {Reason.TREE_ENTRY_LIMIT}, limits=SnapshotLimits(max_tree_entries=5))


@pytest.mark.parametrize("field", ["max_total_bytes", "max_entries", "max_file_bytes", "max_tree_entries"])
def test_limits_cannot_be_loosened(field: str) -> None:
    ceiling = snap.LIMIT_CEILINGS[field]
    for bad in (ceiling + 1, 0, -1, True):
        with pytest.raises(SourceError):
            SnapshotLimits(**{field: bad})


# --- destination and all-or-nothing behaviour --------------------------------------------------


def test_destination_must_be_private_canonical_and_outside_the_repository(registered: RegisteredRepository,
                                                                          repo: Repo, workspace: Path) -> None:
    open_dir = workspace / "open"
    open_dir.mkdir(mode=0o755)
    os.chmod(open_dir, 0o755)
    link = workspace / "dest-link"
    link.symlink_to(private_dir(workspace / "real-dest"))
    inside = private_dir(repo.root / "app" / "out")
    for bad in (open_dir, link, inside, workspace / "missing", repo.root.parent):
        with pytest.raises(SourceError) as e:
            snapshot(registered, "refs/heads/main", SCOPE, bad)
        assert reason_of(e) is Reason.DESTINATION_INVALID, bad


@pytest.mark.parametrize("failure", [OSError("disk full"), KeyboardInterrupt()])
def test_failure_while_writing_leaves_no_partial_snapshot(registered: RegisteredRepository, dest: Path,
                                                          monkeypatch: pytest.MonkeyPatch,
                                                          failure: BaseException) -> None:
    def boom(*_a: Any) -> None:
        raise failure

    monkeypatch.setattr(snap, "_make_read_only", boom)
    with pytest.raises(type(failure)):
        snapshot(registered, "refs/heads/main", SCOPE, dest)
    assert_nothing_produced(dest)


def test_post_write_verification_failure_leaves_nothing(registered: RegisteredRepository, dest: Path,
                                                        monkeypatch: pytest.MonkeyPatch) -> None:
    real_write = snap._write_tree

    def tampering_write(source: Path, plan: Any, contents: list[bytes]) -> None:
        real_write(source, plan, contents)
        (source / "app" / "main.py").write_bytes(b"tampered\n")

    monkeypatch.setattr(snap, "_write_tree", tampering_write)
    with pytest.raises(SourceError) as e:
        snapshot(registered, "refs/heads/main", SCOPE, dest)
    assert reason_of(e) is Reason.SNAPSHOT_VERIFICATION_FAILED
    assert_nothing_produced(dest)


def test_legitimate_non_ascii_and_punctuated_names_are_exported_verbatim(registered: RegisteredRepository,
                                                                        repo: Repo, dest: Path) -> None:
    names = ["app/café.py", "app/文件.txt", "app/with space.py", 'app/quote"d.py', "app/.gitignore"]
    repo.commit_files({n: n.encode() for n in names})
    result = snapshot(registered, "refs/heads/main", SCOPE, dest)
    recorded = {f["path"] for f in result.manifest["files"]}
    for name in names:
        assert name in recorded
        assert (result.source_dir / name).read_bytes() == name.encode()


@pytest.mark.parametrize("setting,reason", [
    (("core.worktree", "../.."), Reason.AMBIGUOUS_REPOSITORY),  # relative to .git: the parent of the root
    (("core.worktree", "/var/empty"), Reason.AMBIGUOUS_REPOSITORY),
    (("core.bare", "true"), Reason.GIT_COMMAND_FAILED),  # Git refuses discovery: "must be run in a work tree"
])
def test_repository_config_cannot_redirect_the_registered_root(repo: Repo, home: Path,
                                                               setting: tuple[str, str], reason: Reason) -> None:
    repo.git("config", *setting)
    before = fingerprint(repo.root)
    with pytest.raises(SourceError) as e:
        register(repo, home)
    assert reason_of(e) is reason, e.value
    assert fingerprint(repo.root) == before


KILL_CHILD = """
import os, signal, sys
from pathlib import Path
from patchproof.git import snapshot as snap
from patchproof.git.command import resolve_git_binary
from patchproof.git.paths import SourceScope
from patchproof.git.repository import register_repository

repo, home, dest = (Path(a) for a in sys.argv[1:4])

def killed(*_args):
    os.kill(os.getpid(), signal.SIGKILL)  # die mid-materialization: no cleanup handler can run

snap._make_read_only = killed
reg = register_repository(repo, resolve_git_binary(), home=home)
snap.create_snapshot(reg, "refs/heads/main", SourceScope.of(["app"]), dest)
"""


def test_force_killed_snapshot_leaves_only_staging_and_never_touches_the_repository(
        repo: Repo, home: Path, dest: Path) -> None:
    import subprocess
    import sys

    (repo.root / "app" / "main.py").write_bytes(b"uncommitted\n")
    before = fingerprint(repo.root)
    proc = subprocess.run([sys.executable, "-c", KILL_CHILD, str(repo.root), str(home), str(dest)],
                          capture_output=True, timeout=120, check=False)
    assert proc.returncode == -9, proc.stderr
    leftovers = [p.name for p in dest.iterdir()]
    assert len(leftovers) == 1 and leftovers[0].startswith(".staging-")  # never a snapshot-* directory
    assert not (dest / leftovers[0] / snap.MANIFEST_NAME).exists()       # no manifest was published
    assert fingerprint(repo.root) == before
    snap.remove_snapshot_tree(dest / leftovers[0])  # PP-014 owns automatic reconciliation of such leftovers
