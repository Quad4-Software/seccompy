# SPDX-License-Identifier: 0BSD
"""Tests for the user notification protocol: structs, flags and Listener."""

import contextlib
import ctypes
import errno
import os
from collections.abc import Callable

import pytest

from seccompy import (
    Action,
    FilterFlag,
    SeccompError,
    UnsupportedError,
    _syscall,
    flag_supported,
    notify,
)

from .conftest import Sandbox, kernel_has_action, requires_seccomp

requires_user_notif = pytest.mark.skipif(
    not kernel_has_action("user_notif") or not flag_supported(FilterFlag.NEW_LISTENER),
    reason="kernel lacks SECCOMP_RET_USER_NOTIF support",
)

NOTIF_FD_SIZE = ctypes.sizeof(_syscall.SeccompNotif)
RESP_FD_SIZE = ctypes.sizeof(_syscall.SeccompNotifResp)
DATA_SIZE = ctypes.sizeof(_syscall.SeccompData)


def fake_sizes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Answer the kernel sizes query with this library's ABI."""
    sizes = _syscall.SeccompNotifSizes(
        seccomp_notif=NOTIF_FD_SIZE,
        seccomp_notif_resp=RESP_FD_SIZE,
        seccomp_data=DATA_SIZE,
    )
    monkeypatch.setattr(_syscall, "notif_sizes", lambda: sizes)


def devnull() -> int:
    return os.dup(0)


def test_ioctl_request_numbers() -> None:
    # Computed the linux/ioctl.h way with magic '!'.
    assert notify._IOCTL_NOTIF_RECV == 0xC0502100
    assert notify._IOCTL_NOTIF_SEND == 0xC0182101
    assert notify._IOCTL_NOTIF_ID_VALID == 0x40082102
    assert notify._IOCTL_NOTIF_ADDFD == 0x40182103
    assert notify._IOCTL_NOTIF_SET_FLAGS == 0x40082104


def test_struct_layouts() -> None:
    assert DATA_SIZE == 64
    assert NOTIF_FD_SIZE == 80
    assert RESP_FD_SIZE == 24
    assert ctypes.sizeof(_syscall.SeccompNotifAddfd) == 24
    assert ctypes.sizeof(_syscall.SeccompNotifSizes) == 6
    data = _syscall.SeccompData()
    assert len(data.args) == 6
    assert _syscall.SeccompData.args.offset == 16
    assert _syscall.SeccompNotif.data.offset == 16


def test_flag_values() -> None:
    assert int(notify.RespFlag.CONTINUE) == 1 << 0
    assert int(notify.AddFdFlag.SETFD) == 1 << 0
    assert int(notify.AddFdFlag.SEND) == 1 << 1
    assert int(notify.FdFlag.SYNC_WAKE_UP) == 1 << 0


def test_user_notif_action_value() -> None:
    assert int(Action.USER_NOTIF) == 0x7FC00000


@requires_seccomp
def test_sizes_matches_kernel() -> None:
    got = notify.sizes()
    assert got == notify._EXPECTED_SIZES
    assert got.seccomp_notif == NOTIF_FD_SIZE
    assert got.seccomp_notif_resp == RESP_FD_SIZE
    assert got.seccomp_data == DATA_SIZE


def test_listener_lifecycle(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_sizes(monkeypatch)
    fd = devnull()
    listener = notify.Listener(fd)
    assert listener.fileno() == fd
    assert not listener.closed
    assert not os.get_inheritable(fd)
    listener.close()
    assert listener.closed
    listener.close()
    with pytest.raises(ValueError, match="closed"):
        listener.fileno()


def test_listener_context_manager(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_sizes(monkeypatch)
    fd = devnull()
    with notify.Listener(fd) as listener:
        assert listener.fileno() == fd
    assert listener.closed
    with pytest.raises(RuntimeError, match="closed"):
        listener.__enter__()


def test_listener_rejects_abi_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    bad = _syscall.SeccompNotifSizes(
        seccomp_notif=NOTIF_FD_SIZE + 16,
        seccomp_notif_resp=RESP_FD_SIZE,
        seccomp_data=DATA_SIZE,
    )
    monkeypatch.setattr(_syscall, "notif_sizes", lambda: bad)
    fd = devnull()
    try:
        with pytest.raises(UnsupportedError, match="ABI"):
            notify.Listener(fd)
    finally:
        with contextlib.suppress(OSError):
            os.close(fd)
    # The fd is closed when validation fails.
    with pytest.raises(OSError, match="Bad file descriptor"):
        os.fstat(fd)


def test_listener_cannot_be_copied(monkeypatch: pytest.MonkeyPatch) -> None:
    import copy

    fake_sizes(monkeypatch)
    with notify.Listener(devnull()) as listener:
        with pytest.raises(TypeError):
            copy.copy(listener)
        with pytest.raises(TypeError):
            copy.deepcopy(listener)
        assert repr(listener).startswith("Listener(fd=")


def test_ioctl_reaches_non_notify_fd(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_sizes(monkeypatch)
    with notify.Listener(devnull()) as listener:
        # /dev/null has no ioctl handler: the kernel answers ENOTTY.
        with pytest.raises(SeccompError) as exc_info:
            listener.recv()
        assert exc_info.value.errno == errno.ENOTTY
        with pytest.raises(SeccompError) as exc_info:
            listener.respond(1)
        assert exc_info.value.errno == errno.ENOTTY


def test_respond_validates_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_sizes(monkeypatch)
    with notify.Listener(devnull()) as listener:
        with pytest.raises(ValueError, match="id"):
            listener.respond(-1)
        with pytest.raises(ValueError, match="errno"):
            listener.respond(1, error=5000)
        with pytest.raises(ValueError, match="range"):
            listener.respond(1, val=1 << 63)


def test_addfd_validates_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_sizes(monkeypatch)
    with notify.Listener(devnull()) as listener:
        with pytest.raises(ValueError, match="id"):
            listener.addfd(-1, 0)
        with pytest.raises(ValueError, match="fd"):
            listener.addfd(1, -1)
        with pytest.raises(ValueError, match="newfd"):
            listener.addfd(1, 0, newfd=4)


def test_closed_listener_rejects_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_sizes(monkeypatch)
    listener = notify.Listener(devnull())
    listener.close()
    calls: list[Callable[[], object]] = [
        lambda: listener.recv(),
        lambda: listener.respond(1),
        lambda: listener.valid(1),
        lambda: listener.addfd(1, 0),
        lambda: listener.set_flags(notify.FdFlag.NONE),
    ]
    for call in calls:
        with pytest.raises(RuntimeError, match="closed"):
            call()


def test_pidfd_open_bad_pid() -> None:
    with pytest.raises(ValueError, match="pid"):
        notify.pidfd_open(-1)


@requires_seccomp
@requires_user_notif
def test_notify_errno_scenario(sandbox: Sandbox) -> None:
    result = sandbox("notify_errno")
    assert result.returncode == 0, result.stdout + result.stderr


@requires_seccomp
@requires_user_notif
def test_notify_continue_scenario(sandbox: Sandbox) -> None:
    result = sandbox("notify_continue")
    assert result.returncode == 0, result.stdout + result.stderr


@requires_seccomp
@requires_user_notif
def test_notify_dead_scenario(sandbox: Sandbox) -> None:
    result = sandbox("notify_dead")
    assert result.returncode == 0, result.stdout + result.stderr


@requires_seccomp
@requires_user_notif
def test_notify_close_scenario(sandbox: Sandbox) -> None:
    result = sandbox("notify_close")
    assert result.returncode == 0, result.stdout + result.stderr


@requires_seccomp
@requires_user_notif
def test_notify_addfd_scenario(sandbox: Sandbox) -> None:
    result = sandbox("notify_addfd")
    if result.returncode == 77:
        pytest.skip(result.stderr)
    assert result.returncode == 0, result.stdout + result.stderr


@requires_seccomp
def test_pidfd_scenario(sandbox: Sandbox) -> None:
    result = sandbox("pidfd")
    if result.returncode == 77:
        pytest.skip(result.stderr)
    assert result.returncode == 0, result.stdout + result.stderr
