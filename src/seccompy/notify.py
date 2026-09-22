# SPDX-License-Identifier: 0BSD
"""Supervisor side of the seccomp user notification protocol.

A Filter loaded with FilterFlag.NEW_LISTENER returns a notification
file descriptor; rules added with Filter.notify() make matching
syscalls queue a struct seccomp_notif on that fd and block the target
thread until a supervisor answers. Listener wraps the fd with the
SECCOMP_IOCTL_NOTIF_* ioctls:

    filt = Filter(default=Action.ALLOW, flags=FilterFlag.NEW_LISTENER)
    filt.notify("mount")
    listener = filt.load()
    req = listener.recv()
    listener.respond(req.id, error=errno.EPERM)

The fd is pollable: it reads as readable when a notification is
pending, writable while a received notification awaits a response, and
reports end-of-file once the last target thread has exited and been
reaped. Closing it (or letting the supervisor die) completes every
still-blocked notification with ENOSYS.

The supervisor must never invoke a notified syscall itself: it would
queue a notification nobody can answer and block forever. Pick
syscalls the supervisor's own runtime does not call internally.

Per the kernel documentation this mechanism is for performing syscalls
on behalf of a lesser-privileged target, not for implementing security
policy: RespFlag.CONTINUE is subject to a TOCTOU race, since the target
can rewrite pointer arguments while it waits for the response.

Kernel reference: https://docs.kernel.org/userspace-api/seccomp_filter.html
Man page: seccomp_unotify(2)
"""

from __future__ import annotations

import contextlib
import ctypes
import errno
import os
import types
from dataclasses import dataclass
from enum import IntFlag
from typing import Final

from . import _syscall
from .errors import SeccompError, UnsupportedError

__all__ = [
    "AddFdFlag",
    "FdFlag",
    "Listener",
    "NotifSizes",
    "Notification",
    "RespFlag",
    "pidfd_getfd",
    "pidfd_open",
    "sizes",
]

_IOC_WRITE: Final = 1
_IOC_READ: Final = 2
_IOC_MAGIC: Final = ord("!")


def _ioc(direction: int, nr: int, size: int) -> int:
    """Compute an ioctl request the way linux/ioctl.h does."""
    return (direction << 30) | (size << 16) | (_IOC_MAGIC << 8) | nr


_IOCTL_NOTIF_RECV: Final = _ioc(
    _IOC_READ | _IOC_WRITE, 0, ctypes.sizeof(_syscall.SeccompNotif)
)
_IOCTL_NOTIF_SEND: Final = _ioc(
    _IOC_READ | _IOC_WRITE, 1, ctypes.sizeof(_syscall.SeccompNotifResp)
)
_IOCTL_NOTIF_ID_VALID: Final = _ioc(_IOC_WRITE, 2, ctypes.sizeof(ctypes.c_uint64))
_IOCTL_NOTIF_ADDFD: Final = _ioc(
    _IOC_WRITE, 3, ctypes.sizeof(_syscall.SeccompNotifAddfd)
)
_IOCTL_NOTIF_SET_FLAGS: Final = _ioc(_IOC_WRITE, 4, ctypes.sizeof(ctypes.c_uint64))

_MAX_ERRNO: Final = 4095
_U64: Final = 0xFFFFFFFFFFFFFFFF

_IoctlArg = (
    _syscall.SeccompNotif
    | _syscall.SeccompNotifResp
    | _syscall.SeccompNotifAddfd
    | ctypes.c_uint64
)


def _check_id(notif_id: int) -> None:
    if not 0 <= notif_id <= _U64:
        raise ValueError(f"notification id out of range: {notif_id}")


class RespFlag(IntFlag):
    """Flags for Listener.respond(), mirroring SECCOMP_USER_NOTIF_FLAG_*.

    CONTINUE is the only flag the kernel defines; it makes the target's
    syscall execute normally instead of returning a spoofed result.
    """

    NONE = 0
    CONTINUE = 1 << 0


class AddFdFlag(IntFlag):
    """Flags for Listener.addfd(), mirroring SECCOMP_ADDFD_FLAG_*."""

    NONE = 0
    SETFD = 1 << 0
    SEND = 1 << 1


class FdFlag(IntFlag):
    """Flags for Listener.set_flags(), mirroring
    SECCOMP_USER_NOTIF_FD_*. SYNC_WAKE_UP wakes the target on the CPU
    the response was sent from, cutting scheduler latency.
    """

    NONE = 0
    SYNC_WAKE_UP = 1 << 0


@dataclass(frozen=True)
class NotifSizes:
    """The kernel's notification ABI sizes from SECCOMP_GET_NOTIF_SIZES."""

    seccomp_notif: int
    seccomp_notif_resp: int
    seccomp_data: int


@dataclass(frozen=True)
class Notification:
    """A pending notification event returned by Listener.recv().

    id is the cookie that respond(), valid() and addfd() refer back to.
    pid is the target thread id (0 when it lives in a pid namespace the
    supervisor cannot see), and the remaining fields mirror struct
    seccomp_data for the intercepted syscall.
    """

    id: int
    pid: int
    flags: int
    nr: int
    arch: int
    instruction_pointer: int
    args: tuple[int, ...]


_EXPECTED_SIZES: Final = NotifSizes(
    ctypes.sizeof(_syscall.SeccompNotif),
    ctypes.sizeof(_syscall.SeccompNotifResp),
    ctypes.sizeof(_syscall.SeccompData),
)


def sizes() -> NotifSizes:
    """Return the kernel's notification struct sizes.

    SECCOMP_GET_NOTIF_SIZES is the documented ABI-compat check for the
    notification protocol; Listener validates it against the structures
    this library uses at construction time.
    """
    raw = _syscall.notif_sizes()
    return NotifSizes(raw.seccomp_notif, raw.seccomp_notif_resp, raw.seccomp_data)


def pidfd_open(pid: int, flags: int = 0) -> int:
    """Open a pidfd for pid via pidfd_open(2)."""
    fd = _syscall.pidfd_open(pid, flags)
    os.set_inheritable(fd, False)
    return fd


def pidfd_getfd(pidfd: int, fd: int, flags: int = 0) -> int:
    """Duplicate fd from the process pidfd refers to via pidfd_getfd(2).

    The supervisor needs ptrace-level access on the target; the kernel
    answers EPERM otherwise. This is one way to obtain a target's
    notification fd or to read descriptors out of it.
    """
    dup = _syscall.pidfd_getfd(pidfd, fd, flags)
    os.set_inheritable(dup, False)
    return dup


class Listener:
    """A notification fd for the SECCOMP_RET_USER_NOTIF protocol.

    Obtained from Filter.load() when the filter carries
    FilterFlag.NEW_LISTENER; the constructor validates the kernel's
    struct sizes via SECCOMP_GET_NOTIF_SIZES and takes ownership of the
    fd, closing it if validation fails. Use as a context manager or
    call close().
    """

    __slots__ = ("_closed", "_fd")

    def __init__(self, fd: int) -> None:
        self._fd = fd
        self._closed = True
        try:
            kernel = sizes()
        except Exception:
            os.close(fd)
            raise
        if kernel != _EXPECTED_SIZES:
            os.close(fd)
            raise UnsupportedError(
                f"kernel notification ABI mismatch: {kernel} != {_EXPECTED_SIZES}"
            )
        os.set_inheritable(fd, False)
        self._closed = False

    @property
    def closed(self) -> bool:
        """Whether the notification file descriptor has been closed."""
        return self._closed

    def fileno(self) -> int:
        """Return the notification file descriptor for poll/select."""
        if self._closed:
            raise ValueError("listener is closed")
        return self._fd

    def _ioctl(self, request: int, arg: _IoctlArg) -> int:
        if self._closed:
            raise RuntimeError("listener is closed")
        return _syscall.ioctl(self._fd, request, ctypes.byref(arg))

    def recv(self) -> Notification:
        """Wait for and return the next notification event.

        Blocks until a target thread triggers a USER_NOTIF rule; poll
        the fd first to integrate with an event loop. SeccompError with
        ENOENT means the target died while the notification was being
        generated.
        """
        req = _syscall.SeccompNotif()
        self._ioctl(_IOCTL_NOTIF_RECV, req)
        return Notification(
            id=req.id,
            pid=req.pid,
            flags=req.flags,
            nr=req.data.nr,
            arch=req.data.arch,
            instruction_pointer=req.data.instruction_pointer,
            args=tuple(req.data.args),
        )

    def respond(
        self,
        notif_id: int,
        *,
        error: int = 0,
        val: int = 0,
        flags: RespFlag = RespFlag.NONE,
    ) -> None:
        """Send a response for a received notification.

        With error=0 the target's syscall returns val; with error set
        to an errno value the syscall fails with it (the kernel expects
        the negated value, which this method applies). RespFlag.CONTINUE
        instead lets the kernel execute the syscall and requires error
        and val to stay zero.

        SeccompError with ENOENT means the target was interrupted by a
        signal or died before the response arrived; valid() narrows that
        window but cannot close it.
        """
        _check_id(notif_id)
        if not 0 <= error <= _MAX_ERRNO:
            raise ValueError(f"errno out of range: {error}")
        if not -(1 << 63) <= val <= (1 << 63) - 1:
            raise ValueError(f"return value out of range: {val}")
        resp = _syscall.SeccompNotifResp(
            id=notif_id, val=val, error=-error, flags=int(flags)
        )
        self._ioctl(_IOCTL_NOTIF_SEND, resp)

    def addfd(
        self,
        notif_id: int,
        local_fd: int,
        *,
        flags: AddFdFlag = AddFdFlag.NONE,
        newfd: int = 0,
        newfd_flags: int = 0,
    ) -> int:
        """Install local_fd into the target's fd table.

        Returns the fd number allocated in the target, suitable as the
        val of a later respond(). AddFdFlag.SETFD installs at newfd
        instead of the lowest free slot; AddFdFlag.SEND also completes
        the notification atomically so the target's syscall returns the
        new fd number. newfd_flags accepts only O_CLOEXEC. The ioctl
        requires Linux 5.9+ (SEND: 5.14+); older kernels fail it with
        EINVAL.
        """
        _check_id(notif_id)
        if local_fd < 0:
            raise ValueError(f"fd out of range: {local_fd}")
        if newfd != 0 and not flags & AddFdFlag.SETFD:
            raise ValueError("newfd requires AddFdFlag.SETFD")
        req = _syscall.SeccompNotifAddfd(
            id=notif_id,
            flags=int(flags),
            srcfd=local_fd,
            newfd=newfd,
            newfd_flags=newfd_flags,
        )
        return self._ioctl(_IOCTL_NOTIF_ADDFD, req)

    def valid(self, notif_id: int) -> bool:
        """Return whether the notification still awaits a response.

        False means the target's blocked syscall was interrupted or the
        target died; a positive answer can still go stale before the
        next call, so respond() may fail with ENOENT regardless.
        """
        _check_id(notif_id)
        cookie = ctypes.c_uint64(notif_id)
        try:
            self._ioctl(_IOCTL_NOTIF_ID_VALID, cookie)
        except SeccompError as exc:
            if exc.errno == errno.ENOENT:
                return False
            raise
        return True

    def set_flags(self, flags: FdFlag) -> None:
        """Set flags on the notification fd (SECCOMP_IOCTL_NOTIF_SET_FLAGS)."""
        bits = ctypes.c_uint64(int(flags))
        self._ioctl(_IOCTL_NOTIF_SET_FLAGS, bits)

    def close(self) -> None:
        """Close the notification fd. Safe to call twice.

        Any target still blocked on it completes with ENOSYS, which is
        also what happens to all of them if the supervisor dies.
        """
        if not self._closed:
            os.close(self._fd)
            self._closed = True

    def __copy__(self) -> Listener:
        raise TypeError("Listener cannot be copied; it owns a kernel file descriptor")

    def __deepcopy__(self, memo: dict[int, object]) -> Listener:
        raise TypeError("Listener cannot be copied; it owns a kernel file descriptor")

    def __repr__(self) -> str:
        state = "closed" if self._closed else "open"
        return f"{type(self).__name__}(fd={self._fd}, {state})"

    def __enter__(self) -> Listener:
        if self._closed:
            raise RuntimeError("listener is closed")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: types.TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        # __del__ must never raise
        with contextlib.suppress(Exception):
            self.close()
