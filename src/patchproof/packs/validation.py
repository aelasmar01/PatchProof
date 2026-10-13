"""Verification pack validation (PROJECT_SPEC.md 7.1, 7.4; verdict specification section 10).

A pack directory is untrusted input until reviewed and approved. Validation reads it as bytes,
parses Python with `ast` only, and never imports or executes a pack module (INV-01). Every
rule fails closed; nothing is corrected, deduplicated or normalized.

Layout: `pack.json`, `README.md`, `tests/**/test_*.py`, `fixtures/*.json`. Nothing else.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from ..core.records import RecordError, load_record
from ..core.records.pack import PackManifest, RequiredTest

MAX_FILES: Final = 64
MAX_FILE_BYTES: Final = 262144
MAX_TOTAL_BYTES: Final = 2097152
MAX_MANIFEST_BYTES: Final = 65536

# Reviewed fixture contracts: the pack's copy must match byte for byte (hash), so the verifier's
# notion of users, owners and markers equals the data the PP-006 target serves.
FIXTURE_CONTRACTS: Final = {
    "synthetic-documents-v1": "sha256:2cbcf118fddb2cd4e38a9af5e8786911e8f85e292e637102799fd60513129eda",
}

# Modules a pack test may import. The verifier helpers carry every semantic decision.
ALLOWED_IMPORTS: Final = frozenset({"__future__", "patchproof_verifier", "patchproof_verifier.authz",
                                    "patchproof_verifier.documents", "patchproof_verifier.http"})
FORBIDDEN_CALLS: Final = frozenset({"pytest.skip", "pytest.xfail", "pytest.importorskip", "pytest.exit",
                                    "pytest.fail", "eval", "exec", "compile", "__import__", "open", "getattr",
                                    "setattr", "globals", "locals", "vars", "breakpoint"})
FORBIDDEN_NAMES: Final = frozenset({"SecurityTerminal", "BaseException", "Exception"})
SECURITY_HELPERS: Final = frozenset({"assess_unauthorized_read", "assess_unauthenticated_read",
                                     "check.secure", "check.violation", "check.inconclusive"})
FUNCTIONAL_HELPERS: Final = frozenset({"expect_document_read", "expect_identity"})

_NAME_RE: Final = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}")
_PLACEHOLDER_RE: Final = re.compile(r"\{\{|\}\}|\$\{|<%|%>|<<[A-Z_]+>>|@@[A-Z_]+@@"
                                 r"|__[A-Z][A-Z0-9_]*__|\bTODO\b|\bTBD\b")


class PackError(ValueError):
    """The pack is not valid. `code` is a stable reason for callers and reports."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        super().__init__(f"{code}: {detail}")


@dataclass(frozen=True)
class PackFile:
    path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class ValidatedPack:
    root: Path
    manifest: PackManifest
    manifest_sha256: str
    pack_tree_sha256: str
    files: tuple[PackFile, ...]

    @property
    def test_files(self) -> tuple[str, ...]:
        return tuple(sorted({t.nodeid.split("::", 1)[0] for t in self.manifest.tests}))


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def pack_tree_sha256(files: tuple[PackFile, ...]) -> str:
    """SHA-256 of the canonical JSON list of (path, size, sha256), ordered by path bytes."""
    entries = [{"path": f.path, "sha256": f.sha256, "size": f.size}
               for f in sorted(files, key=lambda f: f.path.encode("utf-8"))]
    return _sha256(json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _allowed_path(rel: str) -> bool:
    parts = rel.split("/")
    if rel in ("pack.json", "README.md"):
        return True
    if parts[0] == "tests":
        return len(parts) <= 6 and parts[-1].startswith("test_") and parts[-1].endswith(".py")
    if parts[0] == "fixtures":
        return len(parts) == 2 and parts[1].endswith(".json")
    return False


def _read_regular(path: Path, expected: os.stat_result, rel: str) -> bytes:
    """Open without following symlinks or blocking, then confirm it is still the same regular file.

    This closes the race in which a file is swapped for a FIFO, device or other file
    between lstat and open.
    """
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        st = os.fstat(handle.fileno())
        if not stat.S_ISREG(st.st_mode) or (st.st_dev, st.st_ino) != (expected.st_dev, expected.st_ino):
            raise PackError("PACK_PATH_INVALID", f"{rel} changed type or identity while it was read")
        return handle.read(MAX_FILE_BYTES + 1)


def _read_tree(root: Path) -> dict[str, bytes]:
    """Every regular file under root, read without following symlinks. Refuses anything else."""
    contents: dict[str, bytes] = {}
    total = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in [*dirnames, *filenames]:
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            if not _NAME_RE.fullmatch(name) or name.startswith((".", "__")):
                raise PackError("PACK_PATH_INVALID", f"{rel!r} is not an allowed name")
            st = os.lstat(full)
            if stat.S_ISDIR(st.st_mode):
                if name not in ("tests", "fixtures") and not rel.startswith("tests/"):
                    raise PackError("PACK_PATH_INVALID", f"unexpected directory {rel}")
                continue
            if not stat.S_ISREG(st.st_mode):
                raise PackError("PACK_PATH_INVALID", f"{rel} is a symlink or special file")
            if not _allowed_path(rel):
                raise PackError("PACK_PATH_INVALID", f"{rel} is not part of the pack layout")
            if st.st_size > MAX_FILE_BYTES:
                raise PackError("PACK_TOO_LARGE", f"{rel} exceeds {MAX_FILE_BYTES} bytes")
            total += st.st_size
            if len(contents) >= MAX_FILES or total > MAX_TOTAL_BYTES:
                raise PackError("PACK_TOO_LARGE", "the pack exceeds the file count or size limit")
            data = _read_regular(full, st, rel)
            if len(data) != st.st_size:
                raise PackError("PACK_PATH_INVALID", f"{rel} changed while it was read")
            contents[rel] = data
    return contents


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in (*_strings(k), *_strings(v))]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


def _test_functions(tree: ast.Module) -> dict[str, ast.FunctionDef]:
    """Top-level test functions and test methods of top-level Test classes, keyed as in a node ID."""
    found: dict[str, ast.FunctionDef] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
            if isinstance(node, ast.AsyncFunctionDef):
                raise PackError("PACK_TEST_INVALID", f"{node.name} is async")
            found[node.name] = node
        elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name.startswith("test"):
                    if isinstance(item, ast.AsyncFunctionDef):
                        raise PackError("PACK_TEST_INVALID", f"{item.name} is async")
                    found[f"{node.name}::{item.name}"] = item
    return found


def _check_module(rel: str, source: bytes) -> ast.Module:
    try:
        tree = ast.parse(source.decode("utf-8"), filename=rel)
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise PackError("PACK_TEST_INVALID", f"{rel} is not valid UTF-8 Python") from exc
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                raise PackError("PACK_TEST_INVALID", f"{rel} uses a relative import")
            names = {node.module or ""}
        else:
            names = set()
        if names - ALLOWED_IMPORTS:
            raise PackError("PACK_TEST_INVALID", f"{rel} imports {sorted(names - ALLOWED_IMPORTS)}")
        if isinstance(node, ast.Call) and ast.unparse(node.func) in FORBIDDEN_CALLS:
            raise PackError("PACK_TEST_INVALID", f"{rel} calls {ast.unparse(node.func)}")
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.decorator_list:
            raise PackError("PACK_TEST_INVALID", f"{rel}: decorators (skip, xfail, parametrize) are not allowed")
        if isinstance(node, (ast.Try, ast.TryStar, ast.With)):
            raise PackError("PACK_TEST_INVALID", f"{rel}: try/with blocks could hide a terminal observation")
        if isinstance(node, ast.Name) and node.id in FORBIDDEN_NAMES:
            raise PackError("PACK_TEST_INVALID", f"{rel} refers to {node.id}")
        if isinstance(node, (ast.Global, ast.Nonlocal, ast.Lambda)) or (
                isinstance(node, ast.Attribute) and node.attr.startswith("_")):
            raise PackError("PACK_TEST_INVALID", f"{rel} uses a construct packs may not use")
    return tree


def _calls(function: ast.FunctionDef) -> list[str]:
    return [ast.unparse(n.func) for n in ast.walk(function) if isinstance(n, ast.Call)]


def _check_test(test: RequiredTest, function: ast.FunctionDef) -> None:
    params = [a.arg for a in function.args.args if a.arg != "self"]
    calls = _calls(function)
    if test.kind == "security":
        if "check" not in params:
            raise PackError("PACK_TEST_INVALID", f"{test.id} must take the check fixture")
        terminal = [c for c in calls if c in SECURITY_HELPERS]
        if len(terminal) != 1:
            raise PackError("PACK_TEST_INVALID", f"{test.id} must make exactly one terminal security call")
    else:
        if "check" in params or any(c in SECURITY_HELPERS for c in calls):
            raise PackError("PACK_TEST_INVALID", f"{test.id} is functional and must not use the security helpers")
        if not any(c in FUNCTIONAL_HELPERS for c in calls) and not any(
                isinstance(n, ast.Assert) for n in ast.walk(function)):
            raise PackError("PACK_TEST_INVALID", f"{test.id} has no legitimate-behavior assertion")


def validate_pack(root: Path) -> ValidatedPack:
    """Validate a pack directory completely, or raise PackError. Reads only; imports nothing."""
    raw_root = str(root)
    if not os.path.isabs(raw_root) or os.path.realpath(raw_root) != raw_root:
        raise PackError("PACK_PATH_INVALID", "pack root must be an absolute canonical path")
    if not os.path.isdir(raw_root) or os.path.islink(raw_root):
        raise PackError("PACK_PATH_INVALID", "pack root is not a directory")
    contents = _read_tree(root)
    for required in ("pack.json", "README.md"):
        if required not in contents:
            raise PackError("PACK_INCOMPLETE", f"{required} is missing")
    try:
        contents["README.md"].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PackError("PACK_INCOMPLETE", "README.md is not UTF-8 text") from exc
    if not contents["README.md"].strip():
        raise PackError("PACK_INCOMPLETE", "README.md is empty")

    raw_manifest = contents["pack.json"]
    if len(raw_manifest) > MAX_MANIFEST_BYTES:
        raise PackError("PACK_TOO_LARGE", "pack.json is too large")
    try:
        manifest = load_record(PackManifest, raw_manifest, contract="pack-manifest", max_bytes=MAX_MANIFEST_BYTES)
    except RecordError as exc:
        raise PackError("PACK_MANIFEST_INVALID", "; ".join(exc.problems[:5])) from None
    if any(_PLACEHOLDER_RE.search(s) for s in _strings(json.loads(raw_manifest))):
        raise PackError("PACK_MANIFEST_INVALID", "pack.json contains an unresolved placeholder")

    ids = [t.id for t in manifest.tests]
    nodeids = [t.nodeid for t in manifest.tests]
    if len(set(ids)) != len(ids):
        raise PackError("PACK_MANIFEST_INVALID", "duplicate test ID")
    if len(set(nodeids)) != len(nodeids):
        raise PackError("PACK_MANIFEST_INVALID", "duplicate pytest node ID")

    expected_by_file: dict[str, dict[str, RequiredTest]] = {}
    for test in manifest.tests:
        file, _, name = test.nodeid.partition("::")
        if "[" in name:
            raise PackError("PACK_MANIFEST_INVALID", f"{test.id}: parametrized node IDs are not supported")
        expected_by_file.setdefault(file, {})[name] = test
    test_files = {rel for rel in contents if rel.startswith("tests/")}
    if set(expected_by_file) != test_files:
        raise PackError("PACK_TEST_INVALID", "every test module must be referenced by the manifest and exist")
    for rel, expected in sorted(expected_by_file.items()):
        functions = _test_functions(_check_module(rel, contents[rel]))
        if set(functions) != set(expected):
            raise PackError("PACK_TEST_INVALID", f"{rel} defines tests that differ from the manifest")
        for name, test in expected.items():
            _check_test(test, functions[name])

    contract_hash = FIXTURE_CONTRACTS.get(manifest.fixture_contract)
    if contract_hash is None:
        raise PackError("PACK_FIXTURE_INVALID", f"unknown fixture contract {manifest.fixture_contract}")
    fixture_rel = f"fixtures/{manifest.fixture_contract}.json"
    if fixture_rel not in contents or _sha256(contents[fixture_rel]) != contract_hash:
        raise PackError("PACK_FIXTURE_INVALID", f"{fixture_rel} is missing or differs from the reviewed contract")
    if {rel for rel in contents if rel.startswith("fixtures/")} != {fixture_rel}:
        raise PackError("PACK_FIXTURE_INVALID", "fixtures/ may contain only the contract file")

    files = tuple(PackFile(rel, len(data), _sha256(data)) for rel, data in sorted(contents.items()))
    return ValidatedPack(root=root, manifest=manifest, manifest_sha256=_sha256(raw_manifest),
                         pack_tree_sha256=pack_tree_sha256(files), files=files)


SELFTEST_PACK_ID: Final = "verifier-selftest"


def load_selftest_pack(root: Path) -> ValidatedPack:
    """Load the SYNTHETIC verifier self-test pack (PP-008 gate C).

    The self-test deliberately uses patterns the static policy forbids, to exercise harness
    errors, so the module rules are not applied. The path, layout, size and strict-manifest
    rules are. It is accepted only under its fixed pack ID, and approvals refuse that ID.
    """
    raw_root = str(root)
    if not os.path.isabs(raw_root) or os.path.realpath(raw_root) != raw_root:
        raise PackError("PACK_PATH_INVALID", "pack root must be an absolute canonical path")
    contents = _read_tree(root)
    try:
        manifest = load_record(PackManifest, contents["pack.json"], contract="pack-manifest",
                               max_bytes=MAX_MANIFEST_BYTES)
    except (KeyError, RecordError) as exc:
        raise PackError("PACK_MANIFEST_INVALID", "self-test manifest is missing or invalid") from exc
    if manifest.pack_id != SELFTEST_PACK_ID:
        raise PackError("PACK_MANIFEST_INVALID", "only the verifier self-test pack may be loaded this way")
    files = tuple(PackFile(rel, len(data), _sha256(data)) for rel, data in sorted(contents.items()))
    return ValidatedPack(root=root, manifest=manifest, manifest_sha256=_sha256(contents["pack.json"]),
                         pack_tree_sha256=pack_tree_sha256(files), files=files)
