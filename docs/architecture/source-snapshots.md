# Source snapshots — repository registration and read-only snapshots (PP-005)

**Spec:** `PROJECT_SPEC.md` §9.1, §9.2, §5.2 (snapshot cap), §12.2 (`source-manifests/`)
**ADRs:** ADR-004 (committed snapshots), ADR-007 (hashes are not attestation), ADR-009
(policy is code). **Threat model:** AC-2, TB-2, INV-13.
**Code:** `src/patchproof/git/` · **Schema:** `schemas/source-manifest.schema.json`
**Tests:** `tests/unit/test_git_snapshot.py`, `tests/unit/test_git_isolation.py`

PP-005 provides library services only. The CLI workflow (PP-009) and persisted
registration records (PP-011) come later. Nothing here starts a container.

## Components

| Module | Responsibility |
|---|---|
| `command.py` | Resolve the reviewed Git executable; build the sanitized environment and fixed configuration overrides; typed allowlisted operations; bounded subprocess execution |
| `repository.py` | Register an explicitly selected canonical root; parse and resolve permitted revision identifiers |
| `paths.py` | Tree-path validation, case/normalization collision checks, source scope, secret-file policy |
| `snapshot.py` | Strict parsing of `ls-tree`/`cat-file` output, planning, limits, writing, verification, deterministic manifest |
| `errors.py` | `SourceError` with a stable `Reason` code; escaped, bounded detail text |

## Registration (§9.1)

`register_repository(path, git, home=...)` accepts only:

- an **absolute, canonical** path (`realpath(path) == path`: no symlinks, `..`, or trailing `/`);
- an existing directory owned by the current user;
- that is **not** the home directory or one of its ancestors, nor `/`;
- whose own `.git` is a **real directory** (not a symlink or `gitdir:` file) owned by the user;
- without `objects/info/alternates`, `objects/info/http-alternates`, `info/grafts`,
  `commondir`, or `gitdir` (other object stores, rewritten history, linked layouts);
- for which Git, with `GIT_CEILING_DIRECTORIES` set to the parent, discovers exactly this
  root and `.git`, and reports a non-bare repository.

Registration never searches upward. Selecting a subdirectory, or a plain directory below an
unrelated parent repository (the host's `~/.git`), fails with `NOT_A_REPOSITORY_ROOT`
instead of resolving to the parent. Registration writes nothing.

The object format is read with `rev-parse --show-object-format` and recorded; SHA-1 (40 hex)
and SHA-256 (64 hex) repositories are both supported.

## Revisions

Accepted: a **full** lower-case object ID of the repository's format that names a commit, or
a **fully qualified** `refs/heads/...` / `refs/tags/...` name. Everything else is refused
before Git runs: short names (`main`, which may be both a branch and a tag), `HEAD`,
abbreviations, upper-case IDs, option-like values, and every revision expression (`~`, `^`,
`@{}`, `:`, `..`, `^{}`). Refs are looked up with `show-ref --verify -- <ref>` (exact
name, no DWIM), then peeled with `rev-parse --verify --end-of-options <oid>^{commit}`.
An object ID that names a blob, tree, or tag object is refused (`NOT_A_COMMIT`).

## Snapshot pipeline (§9.2)

1. Resolve to full commit and tree IDs.
2. `ls-tree -r -z -l --full-tree` lists the commit (`--format` is avoided because Git C-quotes
   `%(path)` even under `-z`). The NUL-delimited output is
   parsed strictly: header grammar, full-length IDs, size consistency, unique paths. Every
   path in the commit is validated, and an unsafe name **anywhere** refuses the snapshot:
   empty, `.`, `..`, absolute, backslash, non-UTF-8, control or format characters
   (including zero-width and bidi controls), segments over 255 bytes, paths over 4096
   bytes, and `.git` variants (`.GIT`, `.git.`, `git~1`).
3. The reviewed source scope (`source_scope.include`) selects entries. Inside the scope,
   symlinks (`SYMLINK_ENTRY`), gitlinks/submodules (`GITLINK_ENTRY`), and any non-regular
   mode (`SPECIAL_ENTRY`) are **refused, never silently omitted**. Outside the scope,
   entries are recorded as `OUTSIDE_SOURCE_SCOPE` exclusions.
4. The built-in secret-file policy (`secret-files-1`, in code, not profile data) excludes
   matching files inside the scope and records them as `SECRET_FILE_POLICY`. A **required**
   include path that matches the policy is refused (`SECRET_PATH_REQUIRED`), and a
   required path left with no files is refused (`REQUIRED_PATH_MISSING`).
5. Included paths are checked for case-insensitive and Unicode-normalization collisions,
   including file/directory clashes (`PATH_COLLISION`).
6. Limits are checked from the listing **before any blob is read**: at most 20,000 files,
   10 MiB per file, 100 MiB in total (§5.2). Listing the whole commit is separately bounded
   to 100,000 entries and 64 MiB of output. Callers may tighten limits but not exceed
   these ceilings.
7. `cat-file --batch` reads raw blob bytes (no `--textconv`, no `--filters`). Each object
   must match the requested ID, type `blob`, and the listed size, and its bytes must hash
   to its object ID (SHA-1 or SHA-256). Git LFS pointer files are refused (`LFS_POINTER`).
8. Files are written into a private `.staging-<random>` directory beside the destination with
   `O_CREAT|O_EXCL|O_NOFOLLOW`. They are re-read and compared to the manifest, made read-only
   (files `0444`/`0555`, directories `0555`), and the staging directory is renamed atomically to
   `snapshot-<random>`. Any failure, including interruption, removes the staging directory,
   so a failed request leaves no snapshot. A process killed with SIGKILL can leave a
   `.staging-*` directory. That directory is never named or treated as a snapshot.

The destination must be an absolute canonical directory, owned by the user, with mode
`0700`, and must neither contain nor sit inside the repository. Snapshots contain no `.git`.

## Manifest

`source-manifest.json` (schema `urn:patchproof:schema:source-manifest:1.0`) records:
- the object format, requested revision, full commit and tree IDs, and Git version;
- the inclusion profile (include list, secret policy version, limits) and its SHA-256;
- each file's path, mode, Git object ID, size, and SHA-256;
- the exclusions with reasons, the totals, and `source_tree_sha256` (the SHA-256 of the
  canonical JSON of `files`);
- `uncommitted_changes_included: false`;
- `complete_commit`, which is false whenever anything was excluded.

It is deterministic. Canonical JSON with sorted keys and byte-ordered paths contains no
timestamps, snapshot IDs, or absolute paths, so the same inputs yield byte-identical
manifests.

## Git execution and configuration isolation

- **Executable.**
  - Allowed paths: `/usr/local/bin/git` or `/opt/homebrew/bin/git`, which must resolve
    into a Homebrew `Cellar/git/` keg.
  - The version must be ≥ 2.56.0. The macOS `/usr/bin/git` shim is not accepted.
- **Environment, built from scratch.**
  - Nothing is inherited from `os.environ`, so `GIT_DIR`, `GIT_CONFIG_PARAMETERS`,
    `GIT_CONFIG_COUNT`, `GIT_EXEC_PATH`, alternates, namespaces, trace and SSH variables
    cannot reach Git.
  - `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_SYSTEM=/dev/null`, `GIT_CONFIG_GLOBAL=/dev/null`,
    and `HOME=XDG_CONFIG_HOME=/var/empty` mean the host's global `filter.lfs.*`
    (`required=true`) and `gh` credential helper are never loaded.
  - Also set: `GIT_NO_REPLACE_OBJECTS=1`, `GIT_NO_LAZY_FETCH=1`, `GIT_OPTIONAL_LOCKS=0`,
    `GIT_TERMINAL_PROMPT=0`, `LC_ALL=C`, and a minimal `PATH`.
- **Repository-local config.** Git always reads it and it is untrusted. Fixed `-c`
  overrides, which take precedence over it, neutralize:
  - `core.hooksPath` and `core.fsmonitor`;
  - replace refs and Unicode precomposition;
  - the attributes file;
  - SSH, askpass and credential helpers;
  - every transport (`protocol.allow=never`);
  - submodule recursion;
  - auto-gc and maintenance;
  - `filter.lfs.*`;
  - `safe.bareRepository=explicit`.
- **Global options.** `--no-pager`, `--no-replace-objects`, `--literal-pathspecs`,
  `--no-optional-locks`.
- **Allowlist.** Only five subcommands exist: `version`, `rev-parse`, `show-ref`,
  `cat-file`, `ls-tree`. They are built from typed operation classes whose positional
  values are validated object IDs or ref names, placed after `--` or `--end-of-options`.
  `build_argv` refuses any other operation type and any conversion, write, or transport
  token. Each operation also checks at construction time that its positional arguments
  are genuine `ObjectId`/`RefName` objects, not lookalikes or raw strings.
- **Process control.** Argument arrays only, `shell=False`, an explicit `cwd`, a
  per-operation deadline, a stdout cap (the process is killed when it is reached), and a
  16 KiB stderr cap.
- **What never happens.** No checkout, reset, clean, stash, clone, fetch, push, submodule
  initialization, hook, filter, text conversion, alias, pager, or repository-provided
  script. Original repositories are never mounted into containers.

## Residual risks and limits (not claimed as mitigated)

- **Repository-local configuration is still parsed by Git.**
  - The overrides cover every helper the allowlisted read commands could reach, and
    hostile-config tests show none runs.
  - A Git parser vulnerability triggered by crafted config, refs, packs or objects
    remains. It is mitigated only by requiring a supported patched release (≥ 2.56.0),
    the deadlines and the output caps.
  - An `include.path` that points to a FIFO or a very large file is bounded only by the
    deadline.
- **TOCTOU.** The repository is not locked. A concurrent writer can change refs between
  resolution and reading, but the commit is pinned by its full ID once resolved, and
  objects are immutable and hash-verified.
- **Staging leftovers.** A process killed with SIGKILL can leave a `.staging-*` directory.
  A test shows it is never named `snapshot-*`, never contains a published manifest, and
  that the repository is unchanged. **PP-014 obligation:** reconcile such leftovers
  automatically. Until then, `remove_snapshot_tree` removes them on request.
- **Secret-file policy.**
  - It is a reviewed filename list, not content scanning. Secrets in ordinary source
    files are not detected.
  - Gitleaks scanning is planned for PP-026.
- **Unicode collisions.**
  - Case folding uses Python's Unicode `casefold` after NFC normalization. APFS
    case-insensitivity may differ for rare characters.
  - Any on-disk clash that slips through is refused at write time (`O_EXCL`), not
    overwritten.
- **Owner and permission checks** assume a single local user (§4.1). They do not defend
  against a compromised host account.
