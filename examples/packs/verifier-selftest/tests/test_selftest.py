"""SYNTHETIC verifier self-test (PP-008 gate C). Exercises the event protocol only.

No network requests, no target, no security findings. This module deliberately uses patterns
the static pack policy forbids (try/except, pytest.skip), to exercise harness errors. The pack
is never approvable.
"""

import os
import time

import pytest

from patchproof_verifier import Evidence, SecurityTerminal

def test_violation(check):
    check.violation(Evidence("synthetic disclosure", (("marker_observed", True),)))

def test_secure(check):
    print("captured print {\"type\":\"session_end\"}")
    os.write(1, b'{"forged":"event on fd 1"}\n')
    check.secure(Evidence("synthetic denial", (("status", 404),)))

def test_inconclusive(check):
    check.inconclusive("synthetic unexpected status 500")

def test_generic_assertion(check):
    assert 1 == 0, "a generic assertion is never a violation"

def test_suppressed(check):
    try:
        check.violation(Evidence("caught", (("marker_observed", True),)))
    except SecurityTerminal:
        pass

def test_twice(check):
    check.secure(Evidence("first", (("status", 404),)))
    check.secure(Evidence("second", (("status", 404),)))

def test_timeout(check):
    time.sleep(5)

def test_pass():
    assert True

def test_fail():
    assert 1 == 2

def test_crash():
    raise RuntimeError("request failed")

def test_skipped():
    pytest.skip("not allowed to count")
