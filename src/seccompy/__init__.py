# SPDX-License-Identifier: 0BSD
"""Python bindings for Linux seccomp-BPF syscall filtering.

seccompy lets unprivileged processes sandbox themselves by installing
classic BPF filters that the kernel evaluates on every syscall entry.
Filters are built in pure Python, checked against the native
architecture and loaded through seccomp(2) with no compiler or libbpf.

Kernel reference: https://docs.kernel.org/userspace-api/seccomp_filter.html
"""

import errno

from . import _syscall, notify, testing
from .errors import SeccompError, UnsupportedError
from .filter import Action, ArgCmp, ArgCond, Args, CmpOp, Filter, FilterFlag
from .syscalls import (
    AUDIT_ARCH_AARCH64,
    AUDIT_ARCH_X86_64,
    arch,
    audit_arch,
    syscall_name,
    syscall_nr,
)

__version__ = "0.2.0"

__all__ = [
    "AUDIT_ARCH_AARCH64",
    "AUDIT_ARCH_X86_64",
    "Action",
    "ArgCmp",
    "ArgCond",
    "Args",
    "CmpOp",
    "Filter",
    "FilterFlag",
    "SeccompError",
    "UnsupportedError",
    "__version__",
    "action_supported",
    "arch",
    "audit_arch",
    "flag_supported",
    "notify",
    "supported",
    "syscall_name",
    "syscall_nr",
    "testing",
]


def supported() -> bool:
    """Return whether the running kernel can install seccomp filters.

    Probes SECCOMP_GET_ACTION_AVAIL first. Kernels older than 4.8 lack
    that operation but still support filters, so an EINVAL answer also
    counts as supported when the seccomp syscall itself exists.
    """
    try:
        _syscall.action_avail(int(Action.ALLOW))
    except UnsupportedError:
        try:
            return _syscall.probe_flag(0)
        except UnsupportedError:
            return False
    except SeccompError as exc:
        if exc.errno == errno.EINVAL:
            return True
        raise
    return True


def action_supported(action: Action | int) -> bool:
    """Return whether the kernel accepts a SECCOMP_RET_* action."""
    try:
        _syscall.action_avail(int(action))
    except UnsupportedError:
        return False
    except SeccompError as exc:
        if exc.errno == errno.EINVAL:
            return False
        raise
    return True


def flag_supported(flag: FilterFlag) -> bool:
    """Return whether the kernel accepts a SECCOMP_FILTER_FLAG_* flag."""
    try:
        return _syscall.probe_flag(int(flag))
    except UnsupportedError:
        return False
