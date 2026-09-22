# SPDX-License-Identifier: 0BSD
"""Tests that install real seccomp filters in a child process."""

import os
import signal
from pathlib import Path

import pytest

import seccompy

from .conftest import Sandbox, kernel_has_action, requires_seccomp

pytestmark = [requires_seccomp]


def test_errno_enforcement(sandbox: Sandbox, tmp_path: Path) -> None:
    target = tmp_path / "secret.txt"
    target.write_text("secret")
    result = sandbox("errno", target)
    assert result.returncode == 0, result.stdout + result.stderr


def test_errno_through_libc(sandbox: Sandbox) -> None:
    result = sandbox("errno_libc")
    assert result.returncode == 0, result.stdout + result.stderr


def test_kill_enforcement(sandbox: Sandbox) -> None:
    result = sandbox("kill")
    assert result.returncode == -signal.SIGSYS, result.stdout + result.stderr


def test_trap_delivers_sigsys(sandbox: Sandbox) -> None:
    result = sandbox("trap")
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(not kernel_has_action("log"), reason="kernel lacks SECCOMP_RET_LOG")
def test_log_enforcement(sandbox: Sandbox) -> None:
    result = sandbox("log")
    assert result.returncode == 0, result.stdout + result.stderr


def test_arg_matched_rule(sandbox: Sandbox) -> None:
    result = sandbox("args")
    assert result.returncode == 0, result.stdout + result.stderr


def test_arg_comparison_operators(sandbox: Sandbox, tmp_path: Path) -> None:
    target = tmp_path / "readable.txt"
    target.write_text("data")
    result = sandbox("cmp", target)
    assert result.returncode == 0, result.stdout + result.stderr


def test_far_jump_program_loads(sandbox: Sandbox) -> None:
    result = sandbox("far_jump")
    assert result.returncode == 0, result.stdout + result.stderr


def test_default_errno_action(sandbox: Sandbox) -> None:
    result = sandbox("default_errno")
    assert result.returncode == 0, result.stdout + result.stderr


def test_no_new_privs_set_on_load(sandbox: Sandbox) -> None:
    result = sandbox("nnp")
    assert result.returncode == 0, result.stdout + result.stderr


def test_probe_helper() -> None:
    filt = seccompy.Filter(default=seccompy.Action.ALLOW)
    filt.errno("getpid", 13)
    result = seccompy.testing.probe(filt, lambda: None)
    assert result.ok


def test_probe_reports_kill() -> None:
    filt = seccompy.Filter(default=seccompy.Action.ALLOW)
    filt.kill("getpid")
    result = seccompy.testing.probe(filt, os.getpid)
    assert not result.ok
    assert result.signal == signal.SIGSYS


def test_probe_rejects_loaded_filter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(seccompy._syscall, "set_no_new_privs", lambda: None)
    monkeypatch.setattr(seccompy._syscall, "set_mode_filter", lambda program, flags: 0)
    filt = seccompy.Filter()
    filt.load()
    with pytest.raises(RuntimeError, match="loaded"):
        seccompy.testing.probe(filt, lambda: None)
