"""PP-005: Git execution security — configuration isolation, injection, and malformed output.

A hostile repository or host configuration tries to make Git run a program, rewrite blob
bytes, read another object store, or fetch. "Marker" scripts would create a file if any
of them ever ran; every test asserts no marker exists and the snapshot holds the raw
committed bytes. Malformed-output tests drive the parsers with a scripted executor.
"""

from __future__ import annotations

import os
import random
import stat
import unicodedata
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest
from _git_fixtures import Repo, fingerprint, git, git_binary, make_repo, private_dir

from patchproof.git import command as cmd
from patchproof.git import snapshot as snap
from patchproof.git.command import (
    BASE_ENV,
    COMMAND_CONFIG,
    GLOBAL_OPTIONS,
    MIN_GIT_VERSION,
    CommandResult,
    GitBinary,
    GitRunner,
    ObjectFormat,
    ObjectId,
    build_argv,
    resolve_git_binary,
    run_bounded,
)
from patchproof.git.errors import Reason, SourceError, safe_text
from patchproof.git.paths import SourceScope, check_collisions, validate_tree_path
from patchproof.git.repository import RegisteredRepository, parse_revision, register_repository, resolve_revision
from patchproof.git.snapshot import create_snapshot, git_blob_id, parse_cat_file_batch, parse_ls_tree

FILES = {"app/main.py": b"print('raw bytes')\r\n", "app/data.txt": b"line one\nline two\n"}
# Committed after FILES, so `git add` never normalized them. A checkout would convert data.txt
# to CRLF and run the "evil" filter; a snapshot must contain neither conversion.
ATTRIBUTES = {".gitattributes": b"* filter=evil diff=evil eol=crlf\n"}
SCOPE = SourceScope.of(["app"])


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    return Path(os.path.realpath(tmp_path))


@pytest.fixture
def markers(workspace: Path) -> Path:
    return private_dir(workspace / "markers")


def marker_script(markers: Path, name: str) -> str:
    """A program that would record that it ran. It must never run."""
    path = markers.parent / f"evil-{name}.sh"
    path.write_text(f"#!/bin/sh\ntouch '{markers}/{name}'\ncat\n")
    os.chmod(path, 0o755)
    return str(path)


def assert_no_marker(markers: Path) -> None:
    assert sorted(p.name for p in markers.iterdir()) == []


def make_attributed_repo(path: Path) -> Repo:
    repo = make_repo(path, FILES)
    repo.commit_files(ATTRIBUTES)
    return repo


def register(repo: Repo, workspace: Path) -> RegisteredRepository:
    return register_repository(repo.root, git_binary(), home=private_dir(workspace / "home"))


def snapshot_bytes(reg: RegisteredRepository, dest: Path) -> dict[str, bytes]:
    result = create_snapshot(reg, "refs/heads/main", SCOPE, dest)
    return {f["path"]: (result.source_dir / f["path"]).read_bytes() for f in result.manifest["files"]}


# --- environment -----------------------------------------------------------------------------


def test_environment_is_built_from_scratch(monkeypatch: pytest.MonkeyPatch, workspace: Path) -> None:
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_CONFIG_PARAMETERS", "GIT_EXEC_PATH", "GIT_TRACE",
                "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_SSH_COMMAND", "LD_PRELOAD",
                "DYLD_INSERT_LIBRARIES", "PYTHONPATH"):
        monkeypatch.setenv(key, "/injected")
    runner = GitRunner(binary=git_binary(), root=workspace / "repo")
    read_env = runner.environment(cmd.ShowObjectFormat())
    assert read_env == {**BASE_ENV, "GIT_DIR": str(workspace / "repo" / ".git"),
                        "GIT_CEILING_DIRECTORIES": str(workspace)}
    assert runner.environment(cmd.DiscoverRoot()) == {**BASE_ENV, "GIT_CEILING_DIRECTORIES": str(workspace)}
    assert BASE_ENV["GIT_CONFIG_GLOBAL"] == BASE_ENV["GIT_CONFIG_SYSTEM"] == "/dev/null"
    assert BASE_ENV["GIT_NO_REPLACE_OBJECTS"] == BASE_ENV["GIT_NO_LAZY_FETCH"] == "1"


def test_injected_environment_variables_have_no_effect(monkeypatch: pytest.MonkeyPatch, workspace: Path,
                                                       markers: Path) -> None:
    repo = make_attributed_repo(workspace / "repo")
    other = make_repo(workspace / "other", {"app/main.py": b"OTHER REPOSITORY\n", "app/data.txt": b"x\n"})
    evil_home = private_dir(workspace / "evil-home")
    (evil_home / ".gitconfig").write_text(
        f"[core]\n\tfsmonitor = {marker_script(markers, 'home-fsmonitor')}\n"
        f"[filter \"lfs\"]\n\tprocess = {marker_script(markers, 'home-lfs')}\n\trequired = true\n")
    exec_path = private_dir(workspace / "exec-path")
    for tool in ("git-ls-tree", "git-cat-file", "git-rev-parse"):
        (exec_path / tool).write_text(f"#!/bin/sh\ntouch '{markers}/{tool}'\n")
        os.chmod(exec_path / tool, 0o755)
    trace = workspace / "trace.log"
    injected = {
        "HOME": str(evil_home), "XDG_CONFIG_HOME": str(evil_home),
        "GIT_DIR": str(other.root / ".git"), "GIT_WORK_TREE": str(other.root),
        "GIT_OBJECT_DIRECTORY": str(other.root / ".git" / "objects"),
        "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(other.root / ".git" / "objects"),
        "GIT_CONFIG_GLOBAL": str(evil_home / ".gitconfig"),
        "GIT_CONFIG_PARAMETERS": f"'core.fsmonitor'='{marker_script(markers, 'params')}'",
        "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.hooksPath", "GIT_CONFIG_VALUE_0": str(markers),
        "GIT_EXEC_PATH": str(exec_path), "GIT_TRACE": str(trace), "GIT_TRACE2_EVENT": str(trace),
        "GIT_NAMESPACE": "evil", "GIT_INDEX_FILE": str(workspace / "evil-index"),
        "GIT_REPLACE_REF_BASE": "refs/evil/",
    }
    for key, value in injected.items():
        monkeypatch.setenv(key, value)
    before = fingerprint(repo.root)
    reg = register(repo, workspace)
    got = snapshot_bytes(reg, private_dir(workspace / "dest"))
    assert got == FILES
    assert_no_marker(markers)
    assert not trace.exists() and not (workspace / "evil-index").exists()
    assert fingerprint(repo.root) == before


def test_host_style_global_lfs_filter_is_not_applied(monkeypatch: pytest.MonkeyPatch, workspace: Path,
                                                     markers: Path) -> None:
    """environment.lock.md 5: the host has global filter.lfs.* with required=true."""
    global_cfg = workspace / "host.gitconfig"
    script = marker_script(markers, "lfs")
    global_cfg.write_text(f"[filter \"lfs\"]\n\tclean = {script}\n\tsmudge = {script}\n\tprocess = {script}\n"
                          f"\trequired = true\n[credential]\n\thelper = !{marker_script(markers, 'cred')}\n")
    files = {"app/model.bin": b"\x00\x01binary\xff", ".gitattributes": b"*.bin filter=lfs diff=lfs merge=lfs -text\n"}
    repo = make_repo(workspace / "repo", files)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_cfg))
    monkeypatch.setenv("HOME", str(workspace))
    got = snapshot_bytes(register(repo, workspace), private_dir(workspace / "dest"))
    assert got == {"app/model.bin": files["app/model.bin"]}
    assert_no_marker(markers)


# --- hostile repository configuration ------------------------------------------------------


def hostile_config(markers: Path, workspace: Path) -> str:
    include = workspace / "included.cfg"
    include.write_text(f"[core]\n\tfsmonitor = {marker_script(markers, 'include-fsmonitor')}\n"
                       f"[alias]\n\tls-tree = !{marker_script(markers, 'include-alias')}\n")
    m: Callable[[str], str] = lambda name: marker_script(markers, name)  # noqa: E731
    return (
        f"[core]\n\tfsmonitor = {m('fsmonitor')}\n\thooksPath = {markers}\n\tpager = {m('pager')}\n"
        f"\tsshCommand = {m('ssh')}\n\taskPass = {m('askpass')}\n\talternateRefsCommand = {m('altrefs')}\n"
        f"\tuseReplaceRefs = true\n\tprecomposeUnicode = true\n\tuntrackedCache = true\n"
        f"[filter \"evil\"]\n\tclean = {m('clean')}\n\tsmudge = {m('smudge')}\n\tprocess = {m('process')}\n"
        f"\trequired = true\n"
        f"[diff \"evil\"]\n\ttextconv = {m('textconv')}\n\tcommand = {m('diffcmd')}\n"
        f"[alias]\n\tls-tree = !{m('alias-ls-tree')}\n\tcat-file = !{m('alias-cat-file')}\n"
        f"\trev-parse = !{m('alias-rev-parse')}\n\tshow-ref = !{m('alias-show-ref')}\n"
        f"[credential]\n\thelper = !{m('credential')}\n"
        f"[uploadpack]\n\tpackObjectsHook = {m('packhook')}\n"
        f"[gc]\n\tauto = 1\n[maintenance]\n\tauto = true\n"
        f"[pager]\n\tls-tree = {m('pager-ls-tree')}\n"
        f"[include]\n\tpath = {include}\n"
    )


def install_hooks(repo: Repo, markers: Path) -> None:
    hooks = repo.root / ".git" / "hooks"
    for hook in ("post-checkout", "pre-commit", "post-commit", "reference-transaction", "post-index-change",
                 "fsmonitor-watchman", "pre-auto-gc", "post-rewrite", "push-to-checkout"):
        (hooks / hook).write_text(f"#!/bin/sh\ntouch '{markers}/hook-{hook}'\n")
        os.chmod(hooks / hook, 0o755)


def test_hostile_repository_configuration_runs_nothing(workspace: Path, markers: Path) -> None:
    repo = make_attributed_repo(workspace / "repo")
    for i in range(30):  # loose objects so an auto-gc would have work to do
        repo.blob(f"loose {i}\n".encode())
    with (repo.root / ".git" / "config").open("a") as cfg:
        cfg.write(hostile_config(markers, workspace))
    install_hooks(repo, markers)
    before = fingerprint(repo.root)
    got = snapshot_bytes(register(repo, workspace), private_dir(workspace / "dest"))
    assert got == FILES  # raw committed bytes: no filter, no eol conversion
    assert_no_marker(markers)
    assert fingerprint(repo.root) == before


def test_replacement_objects_are_ignored(workspace: Path) -> None:
    repo = make_repo(workspace / "repo", FILES)
    original = repo.text("rev-parse", "HEAD:app/main.py")
    repo.git("replace", original, repo.blob(b"REPLACED CONTENT\n"))
    assert repo.git("cat-file", "-p", original) == b"REPLACED CONTENT\n"  # replacement is active for normal Git
    got = snapshot_bytes(register(repo, workspace), private_dir(workspace / "dest"))
    assert got["app/main.py"] == FILES["app/main.py"]


def test_replaced_commit_is_not_followed(workspace: Path) -> None:
    repo = make_repo(workspace / "repo", FILES)
    head = repo.text("rev-parse", "HEAD")
    repo.commit_files({"app/main.py": b"decoy\n"})
    repo.git("replace", "-f", head, repo.text("rev-parse", "HEAD"))
    replaced_tree = repo.text("rev-parse", f"{head}^{{tree}}")
    assert replaced_tree != repo.text("--no-replace-objects", "rev-parse", f"{head}^{{tree}}")
    reg = register(repo, workspace)
    result = create_snapshot(reg, head, SCOPE, private_dir(workspace / "dest"))
    assert result.manifest["commit_id"] == head
    assert (result.source_dir / "app" / "main.py").read_bytes() == FILES["app/main.py"]


def test_partial_clone_never_lazily_fetches(workspace: Path, markers: Path) -> None:
    origin = make_repo(workspace / "origin", FILES)
    origin.git("config", "uploadpack.allowFilter", "true")
    clone = workspace / "partial"
    git(workspace, "clone", "-q", "--no-checkout", "--filter=blob:none", f"file://{origin.root}", str(clone))
    partial = Repo(clone, "sha1")
    blob = partial.text("rev-parse", "HEAD:app/main.py")
    missing_env_check = ["-c", "protocol.allow=never", "cat-file", "-e", blob]
    with pytest.raises(AssertionError):
        partial.git(*missing_env_check)  # the blob really is absent locally
    before = fingerprint(clone)
    reg = register_repository(clone, git_binary(), home=private_dir(workspace / "home"))
    dest = private_dir(workspace / "dest")
    with pytest.raises(SourceError) as e:
        create_snapshot(reg, "refs/heads/main", SCOPE, dest)
    assert e.value.reason is Reason.MISSING_OBJECT  # `ls-tree -l` reports the absent blob's size as BAD
    assert list(dest.iterdir()) == []
    assert fingerprint(clone) == before  # nothing was fetched into the clone
    with pytest.raises(AssertionError):
        partial.git(*missing_env_check)


# --- the argv surface -------------------------------------------------------------------------


class SmuggledOp:
    op_name = "smuggled"
    discovery = False
    timeout_seconds = 5.0
    stdout_cap = 100

    def argv_tail(self) -> list[str]:
        return ["config", "--global", "core.fsmonitor", "evil"]

    def stdin_bytes(self) -> bytes | None:
        return None


def test_only_allowlisted_operation_types_can_be_run(workspace: Path) -> None:
    with pytest.raises(SourceError) as e:
        build_argv(git_binary(), SmuggledOp())  # type: ignore[arg-type]
    assert e.value.reason is Reason.OPERATION_NOT_ALLOWED


def test_every_argv_has_the_fixed_isolation_prefix() -> None:
    fmt = ObjectFormat.SHA1
    oid = ObjectId("a" * 40, fmt)
    ops: list[Any] = [cmd.Version(), cmd.DiscoverRoot(), cmd.ShowObjectFormat(),
                      cmd.ShowRef(cmd.RefName("refs/heads/x")), cmd.ObjectType(oid), cmd.Peel(oid, "commit"),
                      cmd.LsTree(oid), cmd.CatFileBatch((oid,), stdout_cap=10)]
    binary = git_binary()
    prefix = [binary.real_path, *GLOBAL_OPTIONS]
    for key, value in COMMAND_CONFIG:
        prefix += ["-c", f"{key}={value}"]
    for op in ops:
        argv = build_argv(binary, op)
        assert argv[: len(prefix)] == prefix
        tail = argv[len(prefix):]
        assert tail[0] in cmd.ALLOWED_SUBCOMMANDS
        assert not {"--textconv", "--filters", "--path"} & set(tail)
    with pytest.raises(SourceError):
        cmd.Peel(oid, "blob")


def test_cat_file_batch_never_requests_conversion() -> None:
    op = cmd.CatFileBatch((ObjectId("b" * 40, ObjectFormat.SHA1),), stdout_cap=10)
    assert op.argv_tail() == ["cat-file", "--batch"]
    assert op.stdin_bytes() == b"b" * 40 + b"\n"


def test_deadline_and_output_limits_are_enforced(workspace: Path) -> None:
    started = run_bounded(["/bin/sleep", "30"], env={"PATH": "/usr/bin:/bin"}, cwd=str(workspace),
                          timeout_seconds=0.5, stdout_cap=100)
    assert started.timed_out and not started.ok
    flood = run_bounded(["/usr/bin/yes"], env={"PATH": "/usr/bin:/bin"}, cwd=str(workspace), timeout_seconds=10,
                        stdout_cap=4096)
    assert flood.stdout_truncated and len(flood.stdout) == 4096 and not flood.ok
    with pytest.raises(SourceError) as e:
        cmd._require_ok(started)
    assert e.value.reason is Reason.GIT_TIMEOUT
    with pytest.raises(SourceError) as e:
        cmd._require_ok(flood)
    assert e.value.reason is Reason.GIT_OUTPUT_LIMIT
    with pytest.raises(SourceError):
        run_bounded("git version", env={}, cwd="/", timeout_seconds=1, stdout_cap=1)  # type: ignore[arg-type]


def test_reviewed_git_version_is_required(workspace: Path) -> None:
    real = git_binary()
    assert real.version >= MIN_GIT_VERSION and real.real_path.startswith(cmd.ALLOWED_GIT_REAL_PREFIXES)
    old = private_dir(workspace / "Cellar" / "git" / "2.42.0" / "bin") / "git"
    old.write_text("#!/bin/sh\necho 'git version 2.42.0'\n")
    os.chmod(old, 0o755)
    with pytest.raises(SourceError) as e:
        resolve_git_binary([str(old)], [str(workspace / "Cellar" / "git") + "/"])
    assert e.value.reason is Reason.GIT_VERSION_UNSUPPORTED
    with pytest.raises(SourceError) as e:
        resolve_git_binary([str(old)])  # outside the allowed install locations
    assert e.value.reason is Reason.GIT_BINARY_UNAVAILABLE
    with pytest.raises(SourceError) as e:
        resolve_git_binary([str(workspace / "nope")])
    assert e.value.reason is Reason.GIT_BINARY_UNAVAILABLE
    assert cmd.parse_git_version(b"git version 2.56.0\n") == (2, 56, 0)
    for bad in (b"", b"git version two\n", b"git version 2.56.0\nextra\n", b"\x1b[0mgit version 2.56.0\n"):
        with pytest.raises(SourceError):
            cmd.parse_git_version(bad)


# --- malformed Git output through a scripted executor -------------------------------------------


FAKE_GIT = GitBinary(path="/usr/local/bin/git", real_path="/usr/local/Cellar/git/9.9.9/bin/git", version=(9, 9, 9))
SHA1 = ObjectFormat.SHA1
C = "c" * 40
T = "d" * 40


def scripted(responses: dict[str, bytes | int]) -> Callable[..., CommandResult]:
    def executor(argv: Sequence[str], *, env: dict[str, str], cwd: str, timeout_seconds: float, stdout_cap: int,
                 stdin: bytes | None = None, op_name: str = "git") -> CommandResult:
        response = responses[op_name]
        if isinstance(response, int):
            return CommandResult(op_name, tuple(argv), response, b"", b"fatal: scripted\n", False, False)
        return CommandResult(op_name, tuple(argv), 0, response, b"", False, False)

    return executor


def fake_repo(responses: dict[str, bytes | int]) -> tuple[RegisteredRepository, GitRunner]:
    root = Path("/nonexistent/repo")
    runner = GitRunner(binary=FAKE_GIT, root=root, executor=scripted(responses))
    return RegisteredRepository(root=root, object_format=SHA1, git=FAKE_GIT), runner


@pytest.mark.parametrize("responses,reason", [
    ({"show-ref": f"{C} refs/heads/other\n".encode()}, Reason.MALFORMED_GIT_OUTPUT),
    ({"show-ref": f"{C} refs/heads/main\n{C} refs/heads/main\n".encode()}, Reason.MALFORMED_GIT_OUTPUT),
    ({"show-ref": f"{C[:39]} refs/heads/main\n".encode()}, Reason.MALFORMED_GIT_OUTPUT),
    ({"show-ref": f"{C.upper()} refs/heads/main\n".encode()}, Reason.MALFORMED_GIT_OUTPUT),
    ({"show-ref": f"{C} refs/heads/main".encode()}, Reason.MALFORMED_GIT_OUTPUT),
    ({"show-ref": 1}, Reason.REF_NOT_FOUND),
    ({"show-ref": f"{C} refs/heads/main\n".encode(), "peel": 128}, Reason.NOT_A_COMMIT),
    ({"show-ref": f"{C} refs/heads/main\n".encode(), "peel": f"{C}\n{T}\n".encode()}, Reason.MALFORMED_GIT_OUTPUT),
    ({"show-ref": f"{C} refs/heads/main\n".encode(), "peel": b"abc\n"}, Reason.MALFORMED_GIT_OUTPUT),
    ({"show-ref": f"{C} refs/heads/main\n".encode(), "peel": b"\xff" * 41}, Reason.MALFORMED_GIT_OUTPUT),
])
def test_malformed_resolution_output_is_refused(responses: dict[str, bytes | int], reason: Reason) -> None:
    repo, runner = fake_repo(responses)
    with pytest.raises(SourceError) as e:
        resolve_revision(repo, "refs/heads/main", runner)
    assert e.value.reason is reason


def test_peeled_commit_must_equal_the_requested_id() -> None:
    repo, runner = fake_repo({"object-type": b"commit\n", "peel": f"{T}\n".encode()})
    with pytest.raises(SourceError) as e:
        resolve_revision(repo, C, runner)
    assert e.value.reason is Reason.MALFORMED_GIT_OUTPUT


def ls_record(mode: str, kind: str, oid: str, size: str, path: bytes) -> bytes:
    return f"{mode} {kind} {oid} {size}\t".encode() + path + b"\0"


@pytest.mark.parametrize("out,reason", [
    (ls_record("100644", "blob", C, "3", b"a"), None),
    (ls_record("100644", "blob", C, "3", b"a")[:-1], Reason.MALFORMED_GIT_OUTPUT),
    (b"100644 blob " + C.encode() + b" 3 a\0", Reason.MALFORMED_GIT_OUTPUT),
    (ls_record("100644", "blob", C[:39], "3", b"a"), Reason.MALFORMED_GIT_OUTPUT),
    (ls_record("100644", "blob", C, "-", b"a"), Reason.MALFORMED_GIT_OUTPUT),
    (ls_record("160000", "commit", C, "3", b"a"), Reason.MALFORMED_GIT_OUTPUT),
    (ls_record("100644", "tag", C, "3", b"a"), Reason.MALFORMED_GIT_OUTPUT),
    (ls_record("1006440", "blob", C, "3", b"a"), Reason.MALFORMED_GIT_OUTPUT),
    (ls_record("100644", "blob", C, "03", b"a"), Reason.MALFORMED_GIT_OUTPUT),
    (ls_record("100644", "blob", C, "3", b"a") * 2, Reason.MALFORMED_GIT_OUTPUT),
    (ls_record("100644", "blob", C, "3", b"../a"), Reason.UNSAFE_PATH),
    (ls_record("100644", "blob", C, "3", b""), Reason.UNSAFE_PATH),
    (ls_record("100644", "blob", C, "BAD", b"a"), Reason.MISSING_OBJECT),
    (b"100644 blob " + C.encode() + b"      7\ta\0", None),
    (b"\0", Reason.MALFORMED_GIT_OUTPUT),
])
def test_ls_tree_parser_is_strict(out: bytes, reason: Reason | None) -> None:
    if reason is None:  # single-space and right-aligned (padded) size columns both parse
        assert [e.path for e in parse_ls_tree(out, SHA1, 10)] == ["a"]
        return
    with pytest.raises(SourceError) as e:
        parse_ls_tree(out, SHA1, 10)
    assert e.value.reason is reason


@pytest.mark.parametrize("mode,kind,size,reason", [
    ("100664", "blob", "3", Reason.SPECIAL_ENTRY),
    ("040000", "tree", "-", Reason.SPECIAL_ENTRY),
    ("120000", "blob", "3", Reason.SYMLINK_ENTRY),
    ("160000", "commit", "-", Reason.GITLINK_ENTRY),
    ("100644", "tree", "-", Reason.OBJECT_TYPE_MISMATCH),
])
def test_entry_kinds_inside_scope(mode: str, kind: str, size: str, reason: Reason) -> None:
    with pytest.raises(SourceError) as e:
        entries = parse_ls_tree(ls_record(mode, kind, C, size, b"app/x"), SHA1, 10)
        snap.plan_snapshot(entries, SCOPE, snap.SnapshotLimits())
    assert e.value.reason is reason


def batch_output(content: bytes, oid: str | None = None, kind: str = "blob") -> tuple[bytes, ObjectId]:
    real = git_blob_id(content, SHA1)
    oid = oid or real
    return f"{oid} {kind} {len(content)}\n".encode() + content + b"\n", ObjectId(oid, SHA1)


def test_cat_file_parser_accepts_exact_output_and_verifies_hashes() -> None:
    out, oid = batch_output(b"hello\n")
    assert parse_cat_file_batch(out, [(oid, 6)]) == [b"hello\n"]
    sha256_content = b"x"
    h = git_blob_id(sha256_content, ObjectFormat.SHA256)
    out256 = f"{h} blob 1\n".encode() + b"x\n"
    assert parse_cat_file_batch(out256, [(ObjectId(h, ObjectFormat.SHA256), 1)]) == [b"x"]


@pytest.mark.parametrize("mutate,reason", [
    (lambda out, oid: oid.value.encode() + b" missing\n", Reason.MISSING_OBJECT),
    (lambda out, oid: out.replace(b" blob ", b" tree "), Reason.OBJECT_TYPE_MISMATCH),
    (lambda out, oid: out.replace(b" 6\n", b" 7\n", 1), Reason.MALFORMED_GIT_OUTPUT),
    (lambda out, oid: out.replace(b"hello", b"HELLO"), Reason.OBJECT_HASH_MISMATCH),
    (lambda out, oid: out[:-1], Reason.MALFORMED_GIT_OUTPUT),
    (lambda out, oid: out + b"extra", Reason.MALFORMED_GIT_OUTPUT),
    (lambda out, oid: out.replace(oid.value.encode(), b"e" * 40), Reason.MALFORMED_GIT_OUTPUT),
    (lambda out, oid: b"", Reason.MALFORMED_GIT_OUTPUT),
])
def test_cat_file_parser_refuses_deviations(mutate: Callable[[bytes, ObjectId], bytes], reason: Reason) -> None:
    out, oid = batch_output(b"hello\n")
    with pytest.raises(SourceError) as e:
        parse_cat_file_batch(mutate(out, oid), [(oid, 6)])
    assert e.value.reason is reason


def test_git_failure_detail_is_escaped_and_bounded() -> None:
    text = safe_text(b"\x1b[31mred\x07\n" + b"x" * 1000)
    assert "\x1b" not in text and "\x07" not in text and "\n" not in text and len(text) < 320


# --- seeded property tests (Hypothesis is not an approved dependency) -------------------------------


ALPHABET = "abcdef0123456789ABCDEF-_./~^:@{}*?[]\\ \t\n\x00\x1bmainHEADrefs/heads/tags/" + "é​"


def random_text(rng: random.Random, max_len: int = 80) -> str:
    return "".join(rng.choice(ALPHABET) for _ in range(rng.randint(0, max_len)))


@pytest.mark.parametrize("seed", range(40))
def test_property_caller_revisions_never_reach_git_as_options_or_expressions(seed: int) -> None:
    rng = random.Random(seed)
    seen: list[tuple[str, ...]] = []

    def recording(argv: Sequence[str], **kwargs: Any) -> CommandResult:
        seen.append(tuple(argv))
        return CommandResult(kwargs["op_name"], tuple(argv), 1, b"", b"", False, False)

    for _ in range(250):
        candidate = random_text(rng)
        if rng.random() < 0.2:
            candidate = "refs/heads/" + candidate
        if rng.random() < 0.1:
            candidate = "".join(rng.choice("0123456789abcdef") for _ in range(rng.choice([7, 39, 40, 41, 64])))
        try:
            parsed = parse_revision(candidate, SHA1)
        except SourceError:
            continue
        value = parsed.value
        assert not value.startswith("-") and not set(value) & set("~^:@{}*?[]\\ \t\n\x00")
        assert ".." not in value
        if isinstance(parsed, ObjectId):
            assert len(value) == 40
        else:
            assert value.startswith(("refs/heads/", "refs/tags/"))
        seen.clear()
        runner = GitRunner(binary=FAKE_GIT, root=Path("/nonexistent/r"), executor=recording)
        repo = RegisteredRepository(root=runner.root, object_format=SHA1, git=FAKE_GIT)
        with pytest.raises(SourceError):
            resolve_revision(repo, candidate, runner)
        for argv in seen:
            tail = argv[len(build_argv(FAKE_GIT, cmd.Version())) - 1:]
            assert tail[0] in cmd.ALLOWED_SUBCOMMANDS
            assert tail[-1] in (value, f"{value}^{{commit}}")
            assert tail[-2] in ("--", "--end-of-options")


@pytest.mark.parametrize("seed", range(40))
def test_property_accepted_paths_are_always_safe(seed: int) -> None:
    rng = random.Random(seed)
    pieces = [b"a", b"B", b".", b"..", b"/", b"\\", b"\x00", b"\x1b", b".git", b"\xc3\xa9", b"\xe2\x80\x8b",
              b"\xff", b" ", b"~1", b"GIT", b"-", b"\n"]
    for _ in range(400):
        raw = b"".join(rng.choice(pieces) for _ in range(rng.randint(1, 12)))
        try:
            path = validate_tree_path(raw)
        except SourceError as exc:
            assert exc.reason is Reason.UNSAFE_PATH
            continue
        segments = path.split("/")
        assert not path.startswith("/") and "" not in segments and "." not in segments and ".." not in segments
        assert all(s.casefold().rstrip(". ") not in (".git", "git~1") for s in segments)
        assert not any(ord(ch) < 0x20 or ch in "\x7f\\​" for ch in path)


@pytest.mark.parametrize("seed", range(20))
def test_property_manifest_is_independent_of_listing_order(seed: int) -> None:
    rng = random.Random(seed)
    contents = {f"app/{rng.choice(['x', 'y', 'z'])}{i}.py": bytes(rng.randrange(256) for _ in range(rng.randint(0, 40)))
                for i in range(rng.randint(1, 30))}
    records = [ls_record("100644", "blob", git_blob_id(c, SHA1), str(len(c)), p.encode()) for p, c in contents.items()]
    records.append(ls_record("100644", "blob", C, "1", b"docs/readme.md"))
    reg = RegisteredRepository(root=Path("/nonexistent/r"), object_format=SHA1, git=FAKE_GIT)
    resolved = snap.ResolvedRevision("refs/heads/main", ObjectId(C, SHA1), ObjectId(T, SHA1))
    manifests = []
    for _ in range(3):
        rng.shuffle(records)
        plan = snap.plan_snapshot(parse_ls_tree(b"".join(records), SHA1, 100), SCOPE, snap.SnapshotLimits())
        manifests.append(snap.canonical_json(snap.build_manifest(
            reg, resolved, SCOPE, snap.SnapshotLimits(), plan, [contents[e.path] for e in plan.included])))
    assert manifests[0] == manifests[1] == manifests[2]


@pytest.mark.parametrize("seed", range(20))
def test_property_any_single_byte_corruption_of_blob_output_is_refused(seed: int) -> None:
    rng = random.Random(seed)
    blobs = [bytes(rng.randrange(256) for _ in range(rng.randint(1, 50))) for _ in range(3)]
    requests = [(ObjectId(git_blob_id(b, SHA1), SHA1), len(b)) for b in blobs]
    out = b"".join(f"{o.value} blob {n}\n".encode() + b + b"\n" for (o, n), b in zip(requests, blobs, strict=True))
    assert parse_cat_file_batch(out, requests) == blobs
    for _ in range(50):
        i = rng.randrange(len(out))
        corrupted = out[:i] + bytes([out[i] ^ (1 << rng.randrange(8))]) + out[i + 1:]
        with pytest.raises(SourceError):
            parse_cat_file_batch(corrupted, requests)


def test_snapshot_files_are_regular_read_only_and_never_symlinks(workspace: Path) -> None:
    repo = make_repo(workspace / "repo", FILES)
    result = create_snapshot(register(repo, workspace), "refs/heads/main", SCOPE, private_dir(workspace / "dest"))
    for dirpath, dirnames, filenames in os.walk(result.source_dir):
        for name in dirnames + filenames:
            st = os.lstat(Path(dirpath) / name)
            assert stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)
            assert not st.st_mode & 0o222


# --- each defence layer on its own (mutation survivors M01, M02, M05, M06, M09, M17) -------------


def test_each_replacement_control_alone_disables_replace_refs(workspace: Path) -> None:
    """Environment, global option, and -c override are independent layers; each must work alone."""
    repo = make_repo(workspace / "repo", FILES)
    original = repo.text("rev-parse", "HEAD:app/main.py")
    repo.git("replace", original, repo.blob(b"REPLACED\n"))
    env = {k: v for k, v in BASE_ENV.items() if k != "GIT_NO_REPLACE_OBJECTS"}
    env["GIT_DIR"] = str(repo.root / ".git")
    layers: dict[str, tuple[dict[str, str], list[str]]] = {
        "none": (env, []),
        "environment": ({**env, "GIT_NO_REPLACE_OBJECTS": BASE_ENV["GIT_NO_REPLACE_OBJECTS"]}, []),
        "global-option": (env, [o for o in GLOBAL_OPTIONS if o == "--no-replace-objects"]),
        "config": (env, ["-c", f"core.useReplaceRefs={dict(COMMAND_CONFIG)['core.useReplaceRefs']}"]),
    }
    outputs = {}
    for name, (layer_env, extra) in layers.items():
        result = run_bounded([git_binary().real_path, *extra, "cat-file", "blob", original], env=layer_env,
                             cwd=str(repo.root / ".git"), timeout_seconds=15, stdout_cap=4096)
        assert result.ok, result.stderr
        outputs[name] = result.stdout
    assert outputs["none"] == b"REPLACED\n"  # the fixture really is replaced without any control
    for name in ("environment", "global-option", "config"):
        assert outputs[name] == FILES["app/main.py"], name


def test_protocol_block_alone_prevents_lazy_fetch(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With GIT_NO_LAZY_FETCH removed, protocol.allow=never must still stop the promisor fetch."""
    origin = make_repo(workspace / "origin", FILES)
    origin.git("config", "uploadpack.allowFilter", "true")
    clone = workspace / "partial"
    git(workspace, "clone", "-q", "--no-checkout", "--filter=blob:none", f"file://{origin.root}", str(clone))
    monkeypatch.delitem(cmd.BASE_ENV, "GIT_NO_LAZY_FETCH")
    before = fingerprint(clone)
    reg = register_repository(clone, git_binary(), home=private_dir(workspace / "home"))
    dest = private_dir(workspace / "dest")
    with pytest.raises(SourceError):
        create_snapshot(reg, "refs/heads/main", SCOPE, dest)
    assert list(dest.iterdir()) == []
    assert fingerprint(clone) == before  # no object was fetched into the clone


# Reviewed override table. Behavioural tests show none of these helpers can run through the
# allowlisted commands; this pins the defence-in-depth layer so no override is dropped silently.
REVIEWED_COMMAND_CONFIG = (
    ("core.hooksPath", "/dev/null"), ("core.fsmonitor", "false"), ("core.untrackedCache", "false"),
    ("core.useReplaceRefs", "false"), ("core.precomposeUnicode", "false"), ("core.attributesFile", "/dev/null"),
    ("core.sshCommand", "/usr/bin/false"), ("core.askPass", "/usr/bin/false"), ("credential.helper", ""),
    ("protocol.allow", "never"), ("submodule.recurse", "false"), ("fetch.recurseSubmodules", "false"),
    ("gc.auto", "0"), ("maintenance.auto", "false"), ("filter.lfs.required", "false"), ("filter.lfs.process", ""),
    ("filter.lfs.smudge", ""), ("filter.lfs.clean", ""), ("safe.bareRepository", "explicit"),
)


def test_configuration_overrides_match_the_reviewed_table() -> None:
    assert COMMAND_CONFIG == REVIEWED_COMMAND_CONFIG
    assert GLOBAL_OPTIONS == ("--no-pager", "--no-replace-objects", "--literal-pathspecs", "--no-optional-locks")


class LookalikeOp:
    """Duck-types an allowlisted operation and uses an allowed subcommand, but is not one."""

    op_name = "cat-file-batch"
    discovery = False
    timeout_seconds = 5.0
    stdout_cap = 100

    def argv_tail(self) -> list[str]:
        return ["cat-file", "--batch-all-objects", "--batch"]

    def stdin_bytes(self) -> bytes | None:
        return None


def test_operation_type_allowlist_rejects_lookalikes_with_allowed_subcommands() -> None:
    with pytest.raises(SourceError) as e:
        build_argv(FAKE_GIT, LookalikeOp())  # type: ignore[arg-type]
    assert e.value.reason is Reason.OPERATION_NOT_ALLOWED


@pytest.mark.parametrize("paths", [
    ["app/Main.py", "app/main.py"],
    ["app/café.py", unicodedata.normalize("NFD", "app/café.py")],
    ["app/STRASSE.py", "app/straße.py"],
    ["app/lib", "app/LIB/x.py"],
    ["App/x.py", "app/y.py"],
])
def test_collision_check_runs_before_any_filesystem_write(paths: list[str]) -> None:
    with pytest.raises(SourceError) as e:
        check_collisions(paths)
    assert e.value.reason is Reason.PATH_COLLISION
    records = b"".join(ls_record("100644", "blob", C, "1", p.encode()) for p in paths)
    with pytest.raises(SourceError) as e:
        scope = SourceScope.of(sorted({p.split("/")[0] for p in paths}))
        snap.plan_snapshot(parse_ls_tree(records, SHA1, 10), scope, snap.SnapshotLimits())
    assert e.value.reason is Reason.PATH_COLLISION


def test_distinct_paths_do_not_collide() -> None:
    check_collisions(["app/a.py", "app/b.py", "app/sub/a.py", "app/café.py"])


class LookalikeId:
    """Has the attributes of ObjectId/RefName but never passed their validation."""

    def __init__(self, value: str) -> None:
        self.value = value
        self.object_format = ObjectFormat.SHA1


@pytest.mark.parametrize("build", [
    lambda v: cmd.ObjectType(v), lambda v: cmd.Peel(v, "commit"), lambda v: cmd.LsTree(v),
    lambda v: cmd.ShowRef(v), lambda v: cmd.CatFileBatch((v,), stdout_cap=10),
])
@pytest.mark.parametrize("value", ["--output=/tmp/x", "--batch-all-objects", "c" * 40])
def test_operations_refuse_unvalidated_positional_values(build: Callable[[Any], Any], value: str) -> None:
    """No operation accepts a lookalike or raw string; every positional is a validated value object."""
    for candidate in (LookalikeId(value), value):
        with pytest.raises(SourceError) as e:
            build(candidate)
        assert e.value.reason is Reason.OPERATION_NOT_ALLOWED


def test_object_ids_require_a_real_object_format() -> None:
    with pytest.raises(SourceError) as e:
        ObjectId("c" * 40, "sha1")  # type: ignore[arg-type]
    assert e.value.reason is Reason.OPERATION_NOT_ALLOWED
    for bad in ("C" * 40, "c" * 39, "c" * 41, "-" + "c" * 39, "c" * 64):
        with pytest.raises(SourceError):
            ObjectId(bad, ObjectFormat.SHA1)
