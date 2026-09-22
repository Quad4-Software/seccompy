# SPDX-License-Identifier: 0BSD
"""Raw ctypes bindings for the seccomp syscall and prctl.

All calls go through libc's syscall(2) wrapper, so no libffi or compiler
is needed. The seccomp syscall number differs per architecture; the
number for the running architecture is chosen at call time.

Kernel reference: https://docs.kernel.org/userspace-api/seccomp_filter.html
"""

import ctypes
import ctypes.util
import errno
import os
import platform
import sys

from .errors import SeccompError, UnsupportedError

PR_SET_NO_NEW_PRIVS = 38

SECCOMP_SET_MODE_FILTER = 1
SECCOMP_GET_ACTION_AVAIL = 2
SECCOMP_GET_NOTIF_SIZES = 3

_SYS_SECCOMP = {
    "x86_64": 317,
    "amd64": 317,
    "aarch64": 277,
    "arm64": 277,
}


class SockFprog(ctypes.Structure):
    """struct sock_fprog: a u16 instruction count and a filter pointer."""

    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.c_void_p),
    ]


_libc: ctypes.CDLL | None = None


def _get_libc() -> ctypes.CDLL:
    global _libc
    if _libc is None:
        if sys.platform != "linux":
            raise UnsupportedError("seccomp is only available on Linux")
        name = ctypes.util.find_library("c")
        _libc = ctypes.CDLL(name or None, use_errno=True)
        _libc.syscall.restype = ctypes.c_long
        _libc.prctl.restype = ctypes.c_int
    return _libc


def _seccomp_nr() -> int:
    machine = platform.machine().lower()
    try:
        return _SYS_SECCOMP[machine]
    except KeyError:
        raise UnsupportedError(f"no seccomp syscall number for {machine}") from None


def _call(*args: object) -> int:
    ret = int(_get_libc().syscall(*args))
    if ret != -1:
        return ret
    err = ctypes.get_errno()
    if err in (errno.ENOSYS, errno.EOPNOTSUPP):
        raise UnsupportedError(err, os.strerror(err))
    raise SeccompError(err, os.strerror(err))


def _seccomp(op: int, flags: int, uargs: object) -> int:
    return _call(_seccomp_nr(), op, flags, uargs)


def action_avail(action: int) -> int:
    """Check whether the kernel supports a seccomp return action."""
    val = ctypes.c_uint32(action)
    return _seccomp(SECCOMP_GET_ACTION_AVAIL, 0, ctypes.byref(val))


def probe_flag(flag: int) -> bool:
    """Return whether a SECCOMP_FILTER_FLAG_* is supported.

    A NULL filter program is passed, so the kernel validates the flag and
    then fails on the bad pointer without installing anything. EINVAL
    means the flag is unknown; EFAULT or EACCES mean it passed flag
    validation.
    """
    try:
        _seccomp(SECCOMP_SET_MODE_FILTER, flag, None)
    except UnsupportedError:
        raise
    except SeccompError as exc:
        if exc.errno == errno.EINVAL:
            return False
        if exc.errno in (errno.EFAULT, errno.EACCES):
            return True
        raise
    return True


def set_no_new_privs() -> None:
    """Set the no_new_privs attribute on the calling thread via prctl."""
    ret = _get_libc().prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    if ret == -1:
        err = ctypes.get_errno()
        raise SeccompError(err, os.strerror(err))


def set_mode_filter(program: bytes, flags: int = 0) -> int:
    """Install a classic BPF filter via SECCOMP_SET_MODE_FILTER."""
    if len(program) % 8 != 0 or not program:
        raise ValueError("program must be a non-empty multiple of 8 bytes")
    insns = len(program) // 8
    if insns > 4096:
        raise ValueError("program exceeds the kernel limit of 4096 instructions")
    buf = (ctypes.c_char * len(program)).from_buffer_copy(program)
    fprog = SockFprog(len=insns, filter=ctypes.addressof(buf))
    return _seccomp(SECCOMP_SET_MODE_FILTER, flags, ctypes.byref(fprog))
