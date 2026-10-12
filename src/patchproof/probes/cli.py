"""Command line for the PP-003 probe suite.

`plan` is Docker-free: it prints the exact create argument arrays, the probe catalogue,
and which execution gates are open. `run` executes the suite and refuses unless the A2
image identity is approved in policy code, the A3 evidence directory already exists
with mode 0700, and the operator confirms interactively (A4). These are procedural
gates in the operator's hands, not a sandbox.

The `patchproof doctor --probe-isolation` entry point (PROJECT_SPEC.md 13.1) lands with
packaging; until then use containers/probes/run_isolation_probes.py.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any

from ..runner.docker_cli import DockerCli, resolve_docker_binary
from ..runner.policy import (
    APPROVED_PROBE_IMAGE_ID,
    INSTALLATION_ID_RE,
    ContainerId,
    ImageId,
    Ownership,
    PolicyViolation,
    Role,
    build_spec,
    script_sha256,
)
from . import evidence as ev
from .catalogue import CATALOGUE, SUITE_VERSION, load_probe_script
from .interpret import SuiteStatus
from .orchestrator import ProbeSuite, check_execution_gates

EXIT_PASSED = 0
EXIT_ISOLATION_FAILED = 1
EXIT_USAGE = 2
EXIT_INCONCLUSIVE = 20
EXIT_BLOCKED = 21

PLAN_ROLES = (
    (Role.TARGET, "target"), (Role.VERIFIER, "verifier"), (Role.MEMORY, "memory"), (Role.PIDS, "pids"),
    (Role.CPU, "cpu"), (Role.STORAGE, "storage"), (Role.LOGFLOOD, "logflood"), (Role.SLEEPER, "sleeper"),
    (Role.DECOY_OTHER_RUN, "sleeper"), (Role.DECOY_FOREIGN, "sleeper"),
)
PLACEHOLDER_TARGET = "0" * 64


def build_plan(image: ImageId) -> dict[str, Any]:
    script = load_probe_script()
    ownership = Ownership(installation_id="inst-" + "0" * 32, run_id="run-" + "0" * 32)
    nonce = "0" * 32
    containers = []
    for role, mode in PLAN_ROLES:
        join = ContainerId(PLACEHOLDER_TARGET) if role is Role.VERIFIER else None
        spec = build_spec(ownership=ownership, role=role, image=image, script=script, args=(mode, nonce),
                          join_target=join)
        argv = [a.replace(PLACEHOLDER_TARGET, "<exact-target-container-id>") for a in ev.render_argv_for_review(spec)]
        containers.append({"role": role.value, "started": not role.is_decoy, "argv": argv})
    return {
        "suite_version": SUITE_VERSION,
        "probe_script_sha256": script_sha256(script),
        "probe_script_bytes": len(script.encode()),
        "placeholders": "run ID, installation ID, nonce, and the target container ID are generated at run time",
        "gates": {
            "A2_approved_image_id": APPROVED_PROBE_IMAGE_ID,
            "A2_matches_requested": APPROVED_PROBE_IMAGE_ID == image.value,
        },
        "containers": containers,
        "probes": [{"id": s.probe_id, "kind": s.kind.value, "evidence": s.evidence.value, "title": s.title,
                    "controls": list(s.controls), "expected": s.expected} for s in CATALOGUE],
    }


def _installation_id(root: Path) -> str:
    path = root / "installation-id"
    if path.exists():
        value = path.read_text("utf-8").strip()
        if not INSTALLATION_ID_RE.fullmatch(value):
            raise PolicyViolation("installation-id file is malformed")
        return value
    value = "inst-" + secrets.token_hex(16)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, (value + "\n").encode())
    finally:
        os.close(fd)
    return value


def _confirm(run_id: str, image: ImageId) -> bool:
    if not sys.stdin.isatty():
        print("refusing: A4 confirmation must be interactive", file=sys.stderr)
        return False
    print(f"About to create, start, and remove about 10 labeled probe containers from {image.value}.")
    print("No image will be pulled. Only containers created by this run are removed, by exact ID.")
    phrase = f"run {run_id[4:16]}"
    answer = input(f"Type '{phrase}' to confirm A4 execution: ")
    return answer.strip() == phrase


def cmd_plan(args: argparse.Namespace) -> int:
    plan = build_plan(ImageId(args.image_id))
    if args.json:
        print(json.dumps(plan, indent=2))
        return EXIT_PASSED
    print(f"PP-003 probe plan ({plan['suite_version']}), script {plan['probe_script_sha256']}")
    print(f"A2 approved image: {plan['gates']['A2_approved_image_id']}")
    for c in plan["containers"]:
        print(f"\n[{c['role']}] {'started' if c['started'] else 'created only (decoy)'}")
        print("  " + " ".join(c["argv"]))
    print(f"\n{len(plan['probes'])} probes:")
    for p in plan["probes"]:
        print(f"  {p['id']:<7} {p['kind']:<17} {p['title']}")
    return EXIT_PASSED


def cmd_run(args: argparse.Namespace) -> int:
    image = ImageId(args.image_id)
    root = Path(args.evidence_root).expanduser()
    check_execution_gates(image, root, operator_confirmed=True)  # A2 and A3 before asking
    run_id = "run-" + secrets.token_hex(16)
    if not _confirm(run_id, image):
        print("A4 not confirmed; nothing was executed or written.", file=sys.stderr)
        return EXIT_BLOCKED
    ownership = Ownership(installation_id=_installation_id(root), run_id=run_id)
    run_dir = ev.create_run_dir(root, ownership)
    home = str(Path.home())
    suite = ProbeSuite(DockerCli(resolve_docker_binary(), home), ownership, image, load_probe_script(),
                       home=home, run_dir=run_dir)
    record = suite.run({"a2_image_approved": True, "a3_evidence_root_verified": True, "a4_operator_confirmed": True})
    status = SuiteStatus(record["suite_status"])
    print(f"suite status: {status.value}")
    execution = record["execution"]
    print(f"execution: {execution['active_elapsed_seconds']} s active of {execution['global_deadline_seconds']} s; "
          f"deadline expired={execution['deadline_expired']}; cleanup={execution['cleanup_status']}")
    for probe in record["probes"]:
        print(f"  {probe['probe_id']:<7} {probe['outcome']:<12} {probe['observed'][:110]}")
    print(f"private evidence: {run_dir}")
    return {
        SuiteStatus.ALL_PLANNED_PROBES_PASSED: EXIT_PASSED,
        SuiteStatus.ISOLATION_FAILED: EXIT_ISOLATION_FAILED,
        SuiteStatus.BLOCKED: EXIT_BLOCKED,
    }.get(status, EXIT_INCONCLUSIVE)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_isolation_probes", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan", help="print the exact planned containers and probes (no Docker)")
    plan.add_argument("--image-id", required=True)
    plan.add_argument("--json", action="store_true")
    run = sub.add_parser("run", help="execute the probe suite (requires A2, A3, A4)")
    run.add_argument("--image-id", required=True)
    run.add_argument("--evidence-root", required=True)
    args = parser.parse_args(argv)
    try:
        return cmd_plan(args) if args.command == "plan" else cmd_run(args)
    except PolicyViolation as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_BLOCKED
