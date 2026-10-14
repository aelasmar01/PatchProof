"""The v0.1 workflow subcommands (PROJECT_SPEC.md 13.1; PP-009). Thin wrappers over `patchproof.workflow`.

Exit codes (PROJECT_SPEC.md 13.2): `run` and `report` use the run's lifecycle and verdict
(lifecycle first). The other commands exit 0 when the requested operation succeeded (or was
already done, unchanged), 21 when it was refused by approval, policy or preflight, and 2 for a
usage error before anything ran. Interactive commands refuse unless standard input and output
are a foreground terminal and no `PATCHPROOF*` variable is set.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer

from ..pack_approval import (
    PAPERTRAIL_PACK_ID,
    NotInteractive,
    _ConsoleTerminal,
    approval_store_root,
    data_root,
    papertrail_target,
    require_terminal,
    run_approval,
)
from ..workflow import exit_codes


class ReportFormat(str, Enum):
    markdown = "markdown"
    json = "json"


def _now() -> datetime:
    return datetime.now(UTC)


class _PromptsOnStderr:
    """`run --json`: the whole conversation (prompts, review, progress) goes to standard error,
    which must be the terminal, so standard output carries only the JSON document."""

    def write(self, text: str) -> None:
        sys.stderr.write(text)
        sys.stderr.flush()

    def read_line(self, prompt: str) -> str:
        sys.stderr.write(prompt)
        sys.stderr.flush()
        line = sys.stdin.readline()
        if not line:
            raise EOFError
        return line.removesuffix("\n")


def _interactive(*, conversation_fd: int = 1) -> None:
    try:
        require_terminal(os.environ, stdout_fd=conversation_fd)
    except NotInteractive as exc:
        sys.stderr.write(f"REFUSED: {exc}. Nothing was read, written or executed.\n")
        raise typer.Exit(exit_codes.BLOCKED) from None


def register(app: typer.Typer) -> None:
    project = typer.Typer(help="Register local repositories.", no_args_is_help=True)
    profile = typer.Typer(help="Preview the reviewed execution profile.", no_args_is_help=True)
    pack = typer.Typer(help="Validate and approve verification packs.", no_args_is_help=True)
    plan = typer.Typer(help="Create, inspect and approve immutable execution plans.", no_args_is_help=True)
    app.add_typer(project, name="project")
    app.add_typer(profile, name="profile")
    app.add_typer(pack, name="pack")
    app.add_typer(plan, name="plan")

    @project.command("add")
    def project_add(path: Annotated[str, typer.Argument(help="Absolute canonical repository root.")]) -> None:
        """Register and explicitly approve a canonical local repository (interactive)."""
        from ..git.command import resolve_git_binary
        from ..runner.profiles import load_profile
        from ..workflow.plans import workflow_environment
        from ..workflow.projects import register_project

        _interactive()
        wenv = workflow_environment()
        target = papertrail_target()
        loaded = load_profile(target.profile_path, expected_sha256=target.profile_sha256)
        code = register_project(path, resolve_git_binary(), wenv.projects, _ConsoleTerminal(), loaded, now=_now)
        raise typer.Exit(exit_codes.OK if code == 0 else exit_codes.BLOCKED)

    @project.command("list")
    def project_list() -> None:
        """List registered projects (read-only)."""
        from ..workflow.plans import workflow_environment
        from ..workflow.safe_text import plain

        for record in workflow_environment().projects.all():
            print(f"{record.project_id}  {plain(record.canonical_path, 1024)}  {record.created_at}  "
                  f"{','.join(record.supported_profiles)}")

    @profile.command("prepare")
    def profile_prepare(
        profile_file: Annotated[Path, typer.Argument(help="The versioned profile file.")],
        check_images: Annotated[bool, typer.Option(
            "--check-images", help="Look up the two approved image IDs locally (read-only; never pulls).")] = False,
    ) -> None:
        """Preview the reviewed profile, its images, limits and deadlines (read-only; no pulls or installs)."""
        from ..runner.docker_cli import DockerCli, resolve_docker_binary
        from ..workflow.previews import prepare_profile

        factory = (lambda: DockerCli(resolve_docker_binary(), str(Path.home()))) if check_images else None
        raise typer.Exit(prepare_profile(profile_file, papertrail_target(), _ConsoleTerminal(),
                                         executor_factory=factory))

    @pack.command("validate")
    def pack_validate(pack_dir: Annotated[Path, typer.Argument(help="The pack directory.")]) -> None:
        """Validate a pack statically (no target code runs); show its approval state. Never approves."""
        from ..workflow.previews import validate_pack_preview

        raise typer.Exit(validate_pack_preview(pack_dir, papertrail_target(), approval_store_root(),
                                               _ConsoleTerminal()))

    @pack.command("approve")
    def pack_approve(pack_id: Annotated[str, typer.Argument(help="The pack ID.")]) -> None:
        """Review hashes, test logic and scope; record explicit approval (interactive)."""
        if pack_id != PAPERTRAIL_PACK_ID:
            sys.stderr.write(f"REFUSED: v0.1 can approve only the reviewed pack {PAPERTRAIL_PACK_ID}.\n")
            raise typer.Exit(exit_codes.BLOCKED)
        _interactive()
        code = run_approval(papertrail_target(), approval_store_root(), _ConsoleTerminal(), now=_now)
        raise typer.Exit(exit_codes.OK if code in (0, 3) else exit_codes.BLOCKED)

    @plan.command("create")
    def plan_create(
        project_id: Annotated[str, typer.Option("--project", help="A registered project ID.")],
        baseline: Annotated[str, typer.Option("--baseline", help="Baseline revision (tag or full commit ID).")],
        candidate: Annotated[str, typer.Option("--candidate", help="Candidate revision (tag or full commit ID).")],
        create_snapshots: Annotated[bool, typer.Option(
            "--create-snapshots", help="Review and create missing source snapshots (interactive).")] = False,
    ) -> None:
        """Resolve revisions and store an inspectable immutable plan. Approves and executes nothing."""
        from ..git.command import resolve_git_binary
        from ..workflow.plans import create_plan, workflow_environment

        if create_snapshots:
            _interactive()
        code, _ = create_plan(workflow_environment(), _ConsoleTerminal(), resolve_git_binary(),
                              project_id=project_id, baseline=baseline, candidate=candidate,
                              create_snapshots=create_snapshots)
        raise typer.Exit(code)

    @plan.command("show")
    def plan_show(plan_id: Annotated[str, typer.Argument(help="A stored plan ID.")]) -> None:
        """Show a stored plan and whether it still equals the plan recomputed now (read-only)."""
        from ..workflow.plans import show_plan, workflow_environment

        raise typer.Exit(show_plan(workflow_environment(), _ConsoleTerminal(), plan_id))

    @plan.command("approve")
    def plan_approve(plan_id: Annotated[str, typer.Argument(help="A stored plan ID.")]) -> None:
        """Bind your single-use run authorization to the exact plan hash (interactive)."""
        from ..workflow.plans import approve_plan, workflow_environment

        _interactive()
        raise typer.Exit(approve_plan(workflow_environment(), _ConsoleTerminal(), plan_id, now=_now))

    @app.command("run")
    def run(
        plan_id: Annotated[str, typer.Argument(help="An approved plan ID.")],
        json_output: Annotated[bool, typer.Option(
            "--json", help="Print only the JSON result on stdout; the conversation moves to stderr.")] = False,
    ) -> None:
        """Execute an unchanged approved plan once, after a typed confirmation (interactive).

        With `--json`, the conversation is on standard error (which must be the terminal) and standard
        output carries only the JSON result, so `patchproof run plan-… --json > result.json` works.
        """
        from ..run_papertrail_once import SystemClock
        from ..runner.docker_cli import DockerCli, resolve_docker_binary
        from ..runner.interrupts import graceful_termination
        from ..workflow.plans import run_plan, workflow_environment

        _interactive(conversation_fd=2 if json_output else 1)
        terminal = _PromptsOnStderr() if json_output else _ConsoleTerminal()
        with graceful_termination():
            result = run_plan(workflow_environment(), terminal, plan_id,
                              lambda: DockerCli(resolve_docker_binary(), str(Path.home())), clock=SystemClock(),
                              now=_now)
        if json_output:
            print(json.dumps(result.document(), indent=2, sort_keys=True))
        raise typer.Exit(result.exit_code)

    @app.command("report")
    def report(
        run_id: Annotated[str, typer.Argument(help="A run ID.")],
        output_format: Annotated[ReportFormat, typer.Option("--format", help="Report format.")] =
            ReportFormat.markdown,
        output: Annotated[Path | None, typer.Option(
            "--output", help="Write to a new file (never overwritten; keeps the exit code without a pipe).")] = None,
    ) -> None:
        """Verify a run's evidence, recompute its verdict and print a safe review report."""
        from ..workflow.reports import (
            RUN_ID_RE,
            OutputError,
            ReportError,
            RunNotFound,
            build_report,
            render_json,
            render_markdown,
            write_output,
        )

        if not RUN_ID_RE.fullmatch(run_id):
            sys.stderr.write("usage error: a run ID is 'run-' followed by 32 lower-case hex digits\n")
            raise typer.Exit(exit_codes.USAGE)
        root = data_root()
        try:
            built = build_report(root, run_id)
            text = render_json(built) if output_format is ReportFormat.json else render_markdown(built)
            if output is not None:
                write_output(output, text, root)
            else:
                sys.stdout.write(text)
        except (ReportError, OSError) as exc:
            sys.stderr.write(f"NO REPORT: {exc}\n")
            usage = isinstance(exc, (RunNotFound, OutputError))
            raise typer.Exit(exit_codes.USAGE if usage else exit_codes.INCONCLUSIVE) from None
        raise typer.Exit(built.exit_code)
