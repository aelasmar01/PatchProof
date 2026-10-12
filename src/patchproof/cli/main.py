"""`patchproof` entry point: `doctor` and `doctor --probe-isolation` (PROJECT_SPEC.md 13.1).

`doctor` is read-only. `doctor --probe-isolation` is a thin wrapper over the accepted
PP-003 `run` path (`patchproof.probes.cli`). It adds no Docker option, image, path, or
policy input: the image is the A2 identity in policy code, the evidence directory is
the fixed A3 location, and the A2/A3 gate checks, interactive A4 confirmation,
deadlines, cleanup, and evidence handling are the runner's own, unchanged.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated

import typer

from ..doctor.assessment import Overall, assess, render_text, report_document
from ..doctor.environment import ReadOnlyHost, collect, evidence_root
from ..probes import cli as probe_cli
from ..runner.policy import APPROVED_PROBE_IMAGE_ID

EXIT_OK = 0
EXIT_BLOCKED = 21  # PROJECT_SPEC.md 13.2: blocked by approval, policy, or preflight

PROBE_BANNER = """\
ACTIVE DOCKER OPERATION: --probe-isolation is not part of the read-only doctor report.
It creates, starts, and removes about 10 labeled probe containers from the approved
probe image. It needs separate owner execution authorization (A4) for each run. The A2
image identity and the A3 evidence directory are checked first, then you must type a
confirmation phrase; nothing is created without it. No image is pulled.
"""

app = typer.Typer(
    name="patchproof",
    help="PatchProof: local application security fix-verification workbench.",
    add_completion=False,  # completion installers would modify shell startup files
    no_args_is_help=True,
    pretty_exceptions_enable=False,  # rich tracebacks print local variable values
)


@app.callback()
def _root() -> None:
    """PatchProof: local application security fix-verification workbench."""


@app.command()
def doctor(
    probe_isolation: Annotated[bool, typer.Option(
        "--probe-isolation",
        help="ACTIVE Docker operation: run the fixed harmless isolation probe suite after interactive "
             "confirmation. Requires separate execution authorization.")] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Print the read-only report as JSON.")] = False,
) -> None:
    """Report environment compatibility without modifying the host."""
    if probe_isolation:
        if json_output:
            raise typer.BadParameter("--json applies to the read-only report only", param_hint="--json")
        raise typer.Exit(run_probe_isolation())
    home = Path.home()
    facts = collect(ReadOnlyHost(home=str(home)), home, evidence_root())
    result = assess(facts)
    if json_output:
        print(json.dumps(report_document(facts, result), indent=2))
    else:
        print(render_text(facts, result))
    raise typer.Exit(EXIT_OK if result.overall is Overall.READY else EXIT_BLOCKED)


def run_probe_isolation() -> int:
    print(PROBE_BANNER, file=sys.stderr)
    image = APPROVED_PROBE_IMAGE_ID
    if image is None:
        print("refused: A2 not satisfied: no approved probe image identity is recorded in policy code",
              file=sys.stderr)
        return EXIT_BLOCKED
    return probe_cli.main(["run", "--image-id", image, "--evidence-root", str(evidence_root())])


def main() -> None:
    app(prog_name="patchproof")
