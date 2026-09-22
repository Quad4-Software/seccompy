# SPDX-License-Identifier: 0BSD
"""Raw ctypes bindings for the seccomp syscall, prctl, ioctl and pidfd.

All calls go through libc's syscall(2) wrapper, so no libffi or compiler
is needed. The syscall numbers differ per architecture. The numbers for
the running architecture are chosen at call time.

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

# (pidfd_open, pidfd_getfd), identical on all supported architectures.
_SYS_PIDFD = {
    "x86_64": (434, 438),
    "amd64": (434, 438),
    "aarch64": (434, 438),
    "arm64": (434, 438),
}


class SockFprog(ctypes.Structure):
    """struct sock_fprog: a u16 instruction count and a filter pointer."""

    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.c_void_p),
    ]


class SeccompData(ctypes.Structure):
    """struct seccomp_data: the record a filter or notification sees."""

    _fields_ = [
        ("nr", ctypes.c_int32),
        ("arch", ctypes.c_uint32),
        ("instruction_pointer", ctypes.c_uint64),
        ("args", ctypes.c_uint64 * 6),
    ]


class SeccompNotif(ctypes.Structure):
    """struct seccomp_notif: one pending USER_NOTIF event."""

    _fields_ = [
        ("id", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("data", SeccompData),
    ]


class SeccompNotifResp(ctypes.Structure):
    """struct seccomp_notif_resp: the supervisor's answer to an event."""

    _fields_ = [
        ("id", ctypes.c_uint64),
        ("val", ctypes.c_int64),
        ("error", ctypes.c_int32),
        ("flags", ctypes.c_uint32),
    ]


class SeccompNotifAddfd(ctypes.Structure):
    """struct seccomp_notif_addfd: fd injection into a target."""

    _fields_ = [
        ("id", ctypes.c_uint64),
        ("flags", ctypes.c_uint32),
        ("srcfd", ctypes.c_uint32),
        ("newfd", ctypes.c_uint32),
        ("newfd_flags", ctypes.c_uint32),
    ]


class SeccompNotifSizes(ctypes.Structure):
    """struct seccomp_notif_sizes: the kernel's notification ABI sizes."""

    _fields_ = [
        ("seccomp_notif", ctypes.c_uint16),
        ("seccomp_notif_resp", ctypes.c_uint16),
        ("seccomp_data", ctypes.c_uint16),
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
        _libc.ioctl.restype = ctypes.c_int
    return _libc


def _arch_nr(table: dict[str, int], name: str) -> int:
    machine = platform.machine().lower()
    try:
        return table[machine]
    except KeyError:
        raise UnsupportedError(f"no {name} syscall number for {machine}") from None


def _seccomp_nr() -> int:
    return _arch_nr(_SYS_SECCOMP, "seccomp")


def _pidfd_nr() -> tuple[int, int]:
    machine = platform.machine().lower()
    try:
        return _SYS_PIDFD[machine]
    except KeyError:
        raise UnsupportedError(f"no pidfd syscall numbers for {machine}") from None


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
    means the flag is unknown. EFAULT or EACCES mean it passed flag
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


def notif_sizes() -> SeccompNotifSizes:
    """Query the kernel's notification struct sizes.

    The SECCOMP_GET_NOTIF_SIZES operation is the documented ABI-compat
    mechanism for the user notification protocol: the kernel reports the
    sizes of the structures it expects.
    """
    sizes = SeccompNotifSizes()
    _seccomp(SECCOMP_GET_NOTIF_SIZES, 0, ctypes.byref(sizes))
    return sizes


def ioctl(fd: int, request: int, arg: object) -> int:
    """Call ioctl(2) on fd, preserving the kernel errno on failure."""
    ret = int(_get_libc().ioctl(fd, request, arg))
    if ret == -1:
        err = ctypes.get_errno()
        if err in (errno.ENOSYS, errno.EOPNOTSUPP):
            raise UnsupportedError(err, os.strerror(err))
        raise SeccompError(err, os.strerror(err))
    return ret


def pidfd_open(pid: int, flags: int = 0) -> int:
    """Open a pidfd for a process via pidfd_open(2)."""
    if not 0 <= pid <= 0x7FFFFFFF:
        raise ValueError(f"pid out of range: {pid}")
    return _call(_pidfd_nr()[0], pid, flags)


def pidfd_getfd(pidfd: int, fd: int, flags: int = 0) -> int:
    """Duplicate fd from the process pidfd refers to via pidfd_getfd(2).

    Requires ptrace-level access on the target process. The kernel
    raises EPERM when the caller may not inspect it.
    """
    return _call(_pidfd_nr()[1], pidfd, fd, flags)
