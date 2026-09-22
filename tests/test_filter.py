# SPDX-License-Identifier: 0BSD
"""Tests for Filter construction, compilation and the load path."""

import copy
import ctypes
import errno
import os
import struct
from types import SimpleNamespace

import pytest

from seccompy import Action, Filter, FilterFlag, SeccompError, _syscall, notify
from seccompy.bpf import BPF_JEQ, BPF_LD_ABS_W, BPF_RET_K


@pytest.fixture
def fake_kernel(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Replace the syscall layer with a recorder."""
    calls = SimpleNamespace(nnp=0, installed=[])

    monkeypatch.setattr(
        _syscall, "set_no_new_privs", lambda: setattr(calls, "nnp", calls.nnp + 1)
    )
    monkeypatch.setattr(
        _syscall,
        "set_mode_filter",
        lambda program, flags: calls.installed.append((program, flags)) or 0,
    )
    return calls


def insns(prog: bytes) -> list[tuple[int, int, int, int]]:
    return [struct.unpack_from("<HBBI", prog, i * 8) for i in range(len(prog) // 8)]


def test_default_filter_program() -> None:
    filt = Filter(default=Action.ALLOW)
    assert insns(filt.program) == [
        (BPF_LD_ABS_W, 0, 0, 4),
        (BPF_JEQ, 0, 2, 0xC000003E),
        (BPF_LD_ABS_W, 0, 0, 0),
        (BPF_RET_K, 0, 0, int(Action.ALLOW)),
        (BPF_RET_K, 0, 0, int(Action.KILL_PROCESS)),
    ]


def test_rule_dispatch_program() -> None:
    filt = Filter(default=Action.ALLOW)
    filt.errno("getpid", errno.EACCES)
    filt.kill("ptrace")
    prog = insns(filt.program)

    # arch check, nr load, one jeq per syscall, default ret, rule rets, kill
    assert prog[0] == (BPF_LD_ABS_W, 0, 0, 4)
    assert prog[1][0] == BPF_JEQ
    assert prog[1][3] == 0xC000003E
    assert prog[2] == (BPF_LD_ABS_W, 0, 0, 0)
    assert prog[3] == (BPF_JEQ, 2, 0, 39)
    assert prog[4] == (BPF_JEQ, 2, 0, 101)
    assert prog[5] == (BPF_RET_K, 0, 0, int(Action.ALLOW))
    assert prog[6] == (BPF_RET_K, 0, 0, int(Action.ERRNO) | errno.EACCES)
    assert prog[7] == (BPF_RET_K, 0, 0, int(Action.KILL_PROCESS))
    assert prog[8] == (BPF_RET_K, 0, 0, int(Action.KILL_PROCESS))


def test_arg_rule_loads_both_halves() -> None:
    filt = Filter(default=Action.ALLOW)
    filt.errno("write", errno.EIO, args={0: 0x1_2345_6789})
    prog = insns(filt.program)

    # block for write at index 5: lo check then hi check then ret
    assert prog[5] == (BPF_LD_ABS_W, 0, 0, 16)
    assert prog[6] == (BPF_JEQ, 0, 3, 0x23456789)
    assert prog[7] == (BPF_LD_ABS_W, 0, 0, 20)
    assert prog[8] == (BPF_JEQ, 0, 1, 0x1)
    assert prog[9] == (BPF_RET_K, 0, 0, int(Action.ERRNO) | errno.EIO)
    assert prog[10] == (BPF_RET_K, 0, 0, int(Action.ALLOW))


def test_load_sets_nnp_then_installs(fake_kernel: SimpleNamespace) -> None:
    filt = Filter(default=Action.ALLOW)
    filt.errno("openat", errno.EACCES)
    filt.load()
    assert fake_kernel.nnp == 1
    assert len(fake_kernel.installed) == 1
    program, flags = fake_kernel.installed[0]
    assert program == filt.program
    assert flags == 0
    assert filt.loaded


def test_load_passes_flags(fake_kernel: SimpleNamespace) -> None:
    filt = Filter(flags=FilterFlag.TSYNC | FilterFlag.LOG)
    filt.load()
    assert fake_kernel.installed[0][1] == int(FilterFlag.TSYNC | FilterFlag.LOG)


def test_load_new_listener_returns_listener(
    fake_kernel: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    fd = os.open("/dev/null", os.O_RDONLY)
    monkeypatch.setattr(_syscall, "set_mode_filter", lambda program, flags: fd)
    sizes = _syscall.SeccompNotifSizes(
        seccomp_notif=ctypes.sizeof(_syscall.SeccompNotif),
        seccomp_notif_resp=ctypes.sizeof(_syscall.SeccompNotifResp),
        seccomp_data=ctypes.sizeof(_syscall.SeccompData),
    )
    monkeypatch.setattr(_syscall, "notif_sizes", lambda: sizes)
    filt = Filter(flags=FilterFlag.NEW_LISTENER)
    listener = filt.load()
    assert isinstance(listener, notify.Listener)
    assert listener.fileno() == fd
    listener.close()


def test_load_twice_raises(fake_kernel: SimpleNamespace) -> None:
    filt = Filter()
    filt.load()
    with pytest.raises(RuntimeError, match="loaded"):
        filt.load()


def test_mutation_after_load_raises(fake_kernel: SimpleNamespace) -> None:
    filt = Filter()
    filt.load()
    with pytest.raises(RuntimeError, match="loaded"):
        filt.kill("ptrace")
    with pytest.raises(RuntimeError, match="loaded"):
        filt.errno("openat", errno.EACCES)


def test_load_error_propagates_errno(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_syscall, "set_no_new_privs", lambda: None)

    def deny(program: bytes, flags: int) -> int:
        raise SeccompError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(_syscall, "set_mode_filter", deny)
    filt = Filter()
    with pytest.raises(SeccompError) as exc_info:
        filt.load()
    assert exc_info.value.errno == errno.EACCES
    assert not filt.loaded


def test_filter_cannot_be_copied() -> None:
    filt = Filter()
    with pytest.raises(TypeError):
        copy.copy(filt)
    with pytest.raises(TypeError):
        copy.deepcopy(filt)


def test_unknown_syscall_name() -> None:
    filt = Filter()
    with pytest.raises(ValueError, match="unknown syscall"):
        filt.kill("not_a_syscall")


def test_raw_syscall_number_accepted() -> None:
    filt = Filter()
    filt.kill(101)
    prog = insns(filt.program)
    assert prog[3] == (BPF_JEQ, 1, 0, 101)


def test_syscall_number_range() -> None:
    filt = Filter()
    with pytest.raises(ValueError, match="out of range"):
        filt.kill(-1)
    with pytest.raises(ValueError, match="out of range"):
        filt.kill(1 << 33)


def test_errno_range() -> None:
    filt = Filter()
    with pytest.raises(ValueError, match="errno"):
        filt.errno("getpid", 70000)
    with pytest.raises(ValueError, match="errno"):
        filt.errno("getpid", -1)


def test_arg_index_and_value_range() -> None:
    filt = Filter()
    with pytest.raises(ValueError, match="index"):
        filt.errno("write", errno.EIO, args={6: 0})
    with pytest.raises(ValueError, match="value"):
        filt.errno("write", errno.EIO, args={0: 1 << 64})


def test_default_action_range() -> None:
    with pytest.raises(ValueError, match="default"):
        Filter(default=1 << 40)


def test_program_is_stable_and_cached() -> None:
    filt = Filter()
    filt.kill("ptrace")
    first = filt.program
    assert filt.program == first
    filt.errno("openat", errno.EPERM)
    assert filt.program != first


def test_repr() -> None:
    filt = Filter()
    filt.kill("ptrace")
    assert repr(filt) == "Filter(default=0x7fff0000, rules=1, building)"
