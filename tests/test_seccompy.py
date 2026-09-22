# SPDX-License-Identifier: 0BSD
"""Tests for the package surface: version, exports, probes and errors."""

import errno

import pytest

import seccompy
from seccompy import (
    Action,
    FilterFlag,
    SeccompError,
    UnsupportedError,
    _syscall,
)


def test_version_format() -> None:
    major, minor, patch = seccompy.__version__.split(".")
    assert int(major) >= 0
    assert int(minor) >= 0
    assert int(patch) >= 0


def test_all_exports_exist() -> None:
    for name in seccompy.__all__:
        assert hasattr(seccompy, name), name


def test_action_values() -> None:
    assert int(Action.KILL_PROCESS) == 0x80000000
    assert int(Action.KILL_THREAD) == 0x00000000
    assert Action.__members__["KILL"] is Action.KILL_THREAD
    assert int(Action.TRAP) == 0x00030000
    assert int(Action.ERRNO) == 0x00050000
    assert int(Action.TRACE) == 0x7FF00000
    assert int(Action.LOG) == 0x7FFC0000
    assert int(Action.ALLOW) == 0x7FFF0000


def test_flag_values() -> None:
    assert int(FilterFlag.TSYNC) == 1 << 0
    assert int(FilterFlag.LOG) == 1 << 1
    assert int(FilterFlag.SPEC_ALLOW) == 1 << 2
    assert int(FilterFlag.NEW_LISTENER) == 1 << 3
    assert int(FilterFlag.TSYNC_ESRCH) == 1 << 4
    assert int(FilterFlag.WAIT_KILLABLE_RECV) == 1 << 5


def test_errors_carry_errno() -> None:
    err = SeccompError(errno.EACCES, "denied")
    assert err.errno == errno.EACCES
    assert isinstance(err, OSError)
    assert isinstance(UnsupportedError(errno.ENOSYS, "x"), SeccompError)


def test_supported_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_syscall, "action_avail", lambda action: 0)
    assert seccompy.supported()


def test_supported_false_when_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_enosys(*args: object) -> int:
        raise UnsupportedError(errno.ENOSYS, "Function not implemented")

    monkeypatch.setattr(_syscall, "action_avail", raise_enosys)
    monkeypatch.setattr(_syscall, "probe_flag", raise_enosys)
    assert not seccompy.supported()


def test_supported_true_on_pre_4_8_kernel(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_einval(action: int) -> int:
        raise SeccompError(errno.EINVAL, "Invalid argument")

    monkeypatch.setattr(_syscall, "action_avail", raise_einval)
    assert seccompy.supported()


def test_action_supported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_syscall, "action_avail", lambda action: 0)
    assert seccompy.action_supported(Action.ALLOW)

    def raise_einval(action: int) -> int:
        raise SeccompError(errno.EINVAL, "Invalid argument")

    monkeypatch.setattr(_syscall, "action_avail", raise_einval)
    assert not seccompy.action_supported(Action.LOG)


def test_action_supported_false_when_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_enosys(action: int) -> int:
        raise UnsupportedError(errno.ENOSYS, "Function not implemented")

    monkeypatch.setattr(_syscall, "action_avail", raise_enosys)
    assert not seccompy.action_supported(Action.ALLOW)


def test_flag_supported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_syscall, "probe_flag", lambda flag: flag != 1 << 9)
    assert seccompy.flag_supported(FilterFlag.TSYNC)
    assert not seccompy.flag_supported(FilterFlag(1 << 9))


def test_unexpected_probe_errors_propagate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_efault(action: int) -> int:
        raise SeccompError(errno.EFAULT, "Bad address")

    monkeypatch.setattr(_syscall, "action_avail", raise_efault)
    with pytest.raises(SeccompError):
        seccompy.supported()
    with pytest.raises(SeccompError):
        seccompy.action_supported(Action.ALLOW)


@pytest.mark.skipif(not seccompy.supported(), reason="no seccomp support")
def test_real_kernel_probes() -> None:
    assert seccompy.supported()
    assert seccompy.action_supported(Action.ALLOW)
    assert seccompy.action_supported(Action.ERRNO)
    assert seccompy.flag_supported(FilterFlag.TSYNC)
