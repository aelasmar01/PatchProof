"""PP-008: the proposed (unbuilt) image recipes agree with the code that will verify the built images."""

from __future__ import annotations

import json
import re
from pathlib import Path

from patchproof.runner.policy import APPROVED_PROBE_IMAGE_ID
from patchproof.runner.run_policy import TARGET_HEALTHCHECK

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "containers" / "target-python"
VERIFIER = ROOT / "containers" / "verifier"
PIN = re.compile(r"^([a-z0-9-]+)==([0-9][0-9A-Za-z.]*) \\\n    --hash=sha256:([0-9a-f]{64})$", re.M)


def pins(path: Path) -> dict[str, tuple[str, str]]:
    text = path.read_text()
    found = {m.group(1): (m.group(2), m.group(3)) for m in PIN.finditer(text)}
    body = [line for line in text.splitlines() if line and not line.startswith("#")]
    assert len(body) == 2 * len(found), "every requirement is an exact pin with exactly one hash"
    return found


def test_recipes_are_marked_proposed_and_unbuilt() -> None:
    for recipe in (TARGET / "Dockerfile", VERIFIER / "Dockerfile"):
        text = recipe.read_text()
        assert "NOT BUILT" in text and "gate B" in text
        assert "--network=none" in text


def test_base_image_is_pinned_by_digest_to_the_reviewed_index() -> None:
    for recipe in (TARGET / "Dockerfile", VERIFIER / "Dockerfile"):
        froms = [line for line in recipe.read_text().splitlines() if line.startswith("FROM ")]
        assert froms == [f"FROM python:3.13-slim@{APPROVED_PROBE_IMAGE_ID}"]


def test_installs_are_offline_wheel_only_and_hash_checked() -> None:
    for recipe in (TARGET / "Dockerfile", VERIFIER / "Dockerfile"):
        text = recipe.read_text()
        for flag in ('"--no-index"', '"--require-hashes"', '"--only-binary", ":all:"', '"--no-compile"'):
            assert flag in text
        assert not re.search(r"\b(curl|wget|apt-get|pip download|git clone|ADD )", text)


def test_dependency_locks() -> None:
    assert pins(TARGET / "requirements.lock") == {
        "uvicorn": ("0.54.0", "505bdb0f318731d45f1f712071fc781a8981f6847a31c902c9f5e652d4f67faf"),
        "click": ("8.5.0", "255bc9599cf7748b4b1a446ccc735421bd08a2ae529a8b88597d3de5664ee360"),
        "h11": ("0.16.0", "63cf8bbe7522de3bf65932fda1d9c2772064ffb3dae62d55932da54b31cb6c86"),
    }
    verifier = pins(VERIFIER / "requirements.lock")
    assert set(verifier) == {"pytest", "iniconfig", "packaging", "pluggy", "pygments"}
    assert verifier["pytest"] == ("9.0.3", "2c5efc453d45394fdd706ade797c0a81091eccd1d6e4bccfcd476e2b8e0ab5d9")
    assert not {"httpx", "httpcore", "anyio", "certifi"} & set(verifier)


def test_target_healthcheck_in_the_recipe_equals_the_reviewed_constant() -> None:
    text = (TARGET / "Dockerfile").read_text()
    match = re.search(r"HEALTHCHECK --interval=1s --timeout=2s --start-period=30s --start-interval=1s "
                      r"--retries=3 \\\n    CMD (\[.*\])\n", text)
    assert match is not None
    assert ["CMD", *json.loads(match.group(1))] == TARGET_HEALTHCHECK["Test"]
    assert (TARGET_HEALTHCHECK["Interval"], TARGET_HEALTHCHECK["Timeout"], TARGET_HEALTHCHECK["StartPeriod"],
            TARGET_HEALTHCHECK["StartInterval"], TARGET_HEALTHCHECK["Retries"]) == (
        1_000_000_000, 2_000_000_000, 30_000_000_000, 1_000_000_000, 3)
    assert "HEALTHCHECK" not in (VERIFIER / "Dockerfile").read_text()


def test_verifier_image_environment_and_contents() -> None:
    text = (VERIFIER / "Dockerfile").read_text()
    assert "ENV PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 " in text
    assert "/opt/patchproof/verifier/pytest.ini" in text
    assert "COPY --from=verifier" in text and "papertrail" not in text.lower()
    assert "examples" not in text and "/app/source" not in text
    assert "COPY" not in (TARGET / "Dockerfile").read_text()


def test_pip_writes_no_bytecode_during_the_build() -> None:
    """Gate B finding G-B2: pip's own imports left stdlib and site-packages __pycache__ in the layer."""
    for recipe in (TARGET / "Dockerfile", VERIFIER / "Dockerfile"):
        text = recipe.read_text()
        assert '["/usr/local/bin/python3", "-B", "-m", "pip", "install",' in text
        assert '"--no-compile"' in text


def test_verifier_directories_are_created_traversable_before_copy() -> None:
    """Gate B finding G-B1: COPY --chmod=0644 made the created directories 0644 (untraversable)."""
    text = (VERIFIER / "Dockerfile").read_text()
    create = text.index('RUN ["/usr/bin/install", "-d", "-o", "0", "-g", "0", "-m", "0755", ')
    assert create < text.index("COPY --from=verifier")
    for directory in ("/usr/local/lib/python3.13/site-packages/patchproof_verifier", "/opt/patchproof",
                      "/opt/patchproof/verifier"):
        assert f'"{directory}"' in text[create:text.index("COPY --from=verifier")]


def test_verifier_permissions_are_enforced_after_the_final_copy() -> None:
    """Owner requirement: do not rely only on pre-creating directories; enforce modes on the final paths."""
    text = (VERIFIER / "Dockerfile").read_text()
    last_copy = text.rindex("COPY --from=verifier")
    roots = '"/usr/local/lib/python3.13/site-packages/patchproof_verifier", "/opt/patchproof"'
    chown = text.index(f'RUN ["/usr/bin/chown", "-R", "0:0", {roots}]')
    dirs = text.index(f'RUN ["/usr/bin/find", {roots}, "-type", "d", "-exec", "/usr/bin/chmod", "0755", "{{}}", "+"]')
    files = text.index(f'RUN ["/usr/bin/find", {roots}, "-type", "f", "-exec", "/usr/bin/chmod", "0644", "{{}}", "+"]')
    assert last_copy < chown < dirs < files < text.index("USER 10001:10001")
    assert text.rstrip().endswith("USER 10001:10001")
    assert "0777" not in text and "0666" not in text and "chmod -R" not in text and "+w" not in text


def test_approved_run_images_equal_the_gate_b_r2_inspect_records() -> None:
    """The approved records must match the r2 builds exactly; r1 IDs are never approved."""
    from patchproof.runner.run_plan import APPROVED_RUN_IMAGES, REJECTED_RUN_IMAGE_IDS
    from patchproof.runner.run_policy import RunRole

    by_role = {i.role: i for i in APPROVED_RUN_IMAGES}
    assert set(by_role) == {RunRole.TARGET, RunRole.VERIFIER} and len(APPROVED_RUN_IMAGES) == 2
    assert by_role[RunRole.TARGET].image.value == (
        "sha256:98548ec48d8d796fca5adaf4aab3e461bee38210bd1d568281f79190685eac2e")
    assert by_role[RunRole.VERIFIER].image.value == (
        "sha256:e880f609a7c4d292441e22d1d0d5d7c876697dd4e1e657a668b2b6266969fecc")
    assert by_role[RunRole.TARGET].healthcheck == TARGET_HEALTHCHECK
    assert by_role[RunRole.VERIFIER].healthcheck is None
    assert "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1" in by_role[RunRole.VERIFIER].env
    assert "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1" not in by_role[RunRole.TARGET].env
    assert not {i.image.value for i in APPROVED_RUN_IMAGES} & REJECTED_RUN_IMAGE_IDS
