# SPDX-License-Identifier: 0BSD

import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

import seccompy

ROOT = Path(__file__).resolve().parent.parent
HELPER = Path(__file__).resolve().parent / "_sandbox.py"
ACTIONS_AVAIL = Path("/proc/sys/kernel/seccomp/actions_avail")

Sandbox = Callable[..., "subprocess.CompletedProcess[str]"]

requires_seccomp = pytest.mark.skipif(
    not seccompy.supported(), reason="kernel does not support seccomp filters"
)


def kernel_has_action(name: str) -> bool:
    """Return whether actions_avail lists a SECCOMP_RET_* action."""
    try:
        return name in ACTIONS_AVAIL.read_text().split()
    except OSError:
        return False


@pytest.fixture
def sandbox() -> Sandbox:
    """Run a scenario in _sandbox.py under a fresh Python process."""

    def run(scenario: str, *args: object) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
        return subprocess.run(
            [sys.executable, str(HELPER), scenario, *(str(a) for a in args)],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

    return run
