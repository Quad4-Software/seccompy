# SPDX-License-Identifier: 0BSD
"""Tests for the package surface: version, exports, probes and errors."""

import errno

import pytest

import seccompy


def test_version_format() -> None:
    major, minor, patch = seccompy.__version__.split(".")
    assert int(major) >= 0
    assert int(minor) >= 0
    assert int(patch) >= 0


def test_all_exports_exist() -> None:
    for name in seccompy.__all__:
        assert hasattr(seccompy, name), name


def test_action_values() -> None:
    assert int(seccompy.Action.KILL_PROCESS) == 0x80000000
    assert int(seccompy.Action.KILL_THREAD) == 0x00000000
    assert seccompy.Action.__members__["KILL"] is seccompy.Action.KILL_THREAD
    assert int(seccompy.Action.TRAP) == 0x00030000
    assert int(seccompy.Action.ERRNO) == 0x00050000
    assert int(seccompy.Action.TRACE) == 0x7FF00000
    assert int(seccompy.Action.LOG) == 0x7FFC0000
    assert int(seccompy.Action.ALLOW) == 0x7FFF0000


def test_flag_values() -> None:
    assert int(seccompy.FilterFlag.TSYNC) == 1 << 0
    assert int(seccompy.FilterFlag.LOG) == 1 << 1
    assert int(seccompy.FilterFlag.SPEC_ALLOW) == 1 << 2
    assert int(seccompy.FilterFlag.NEW_LISTENER) == 1 << 3
    assert int(seccompy.FilterFlag.TSYNC_ESRCH) == 1 << 4
    assert int(seccompy.FilterFlag.WAIT_KILLABLE_RECV) == 1 << 5


def test_errors_carry_errno() -> None:
    err = seccompy.SeccompError(errno.EACCES, "denied")
    assert err.errno == errno.EACCES
    assert isinstance(err, OSError)
    assert isinstance(
        seccompy.UnsupportedError(errno.ENOSYS, "x"), seccompy.SeccompError
    )


def test_supported_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(seccompy._syscall, "action_avail", lambda action: 0)
    assert seccompy.supported()


def test_supported_false_when_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_enosys(*args: object) -> int:
        raise seccompy.UnsupportedError(errno.ENOSYS, "Function not implemented")

    monkeypatch.setattr(seccompy._syscall, "action_avail", raise_enosys)
    monkeypatch.setattr(seccompy._syscall, "probe_flag", raise_enosys)
    assert not seccompy.supported()


def test_supported_true_on_pre_4_8_kernel(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_einval(action: int) -> int:
        raise seccompy.SeccompError(errno.EINVAL, "Invalid argument")

    monkeypatch.setattr(seccompy._syscall, "action_avail", raise_einval)
    assert seccompy.supported()


def test_action_supported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(seccompy._syscall, "action_avail", lambda action: 0)
    assert seccompy.action_supported(seccompy.Action.ALLOW)

    def raise_einval(action: int) -> int:
        raise seccompy.SeccompError(errno.EINVAL, "Invalid argument")

    monkeypatch.setattr(seccompy._syscall, "action_avail", raise_einval)
    assert not seccompy.action_supported(seccompy.Action.LOG)


def test_action_supported_false_when_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_enosys(action: int) -> int:
        raise seccompy.UnsupportedError(errno.ENOSYS, "Function not implemented")

    monkeypatch.setattr(seccompy._syscall, "action_avail", raise_enosys)
    assert not seccompy.action_supported(seccompy.Action.ALLOW)


def test_flag_supported(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(seccompy._syscall, "probe_flag", lambda flag: flag != 1 << 9)
    assert seccompy.flag_supported(seccompy.FilterFlag.TSYNC)
    assert not seccompy.flag_supported(seccompy.FilterFlag(1 << 9))


def test_unexpected_probe_errors_propagate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_efault(action: int) -> int:
        raise seccompy.SeccompError(errno.EFAULT, "Bad address")

    monkeypatch.setattr(seccompy._syscall, "action_avail", raise_efault)
    with pytest.raises(seccompy.SeccompError):
        seccompy.supported()
    with pytest.raises(seccompy.SeccompError):
        seccompy.action_supported(seccompy.Action.ALLOW)


@pytest.mark.skipif(not seccompy.supported(), reason="no seccomp support")
def test_real_kernel_probes() -> None:
    assert seccompy.supported()
    assert seccompy.action_supported(seccompy.Action.ALLOW)
    assert seccompy.action_supported(seccompy.Action.ERRNO)
    assert seccompy.flag_supported(seccompy.FilterFlag.TSYNC)
