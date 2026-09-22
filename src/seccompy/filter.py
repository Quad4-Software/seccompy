# SPDX-License-Identifier: 0BSD
"""Filter construction and enforcement for seccomp-BPF.

A Filter declares a default action and per-syscall rules, then compiles
to a classic BPF program that the kernel runs against struct
seccomp_data on every syscall entry:

    filt = Filter(default=Action.ALLOW)
    filt.errno("write", errno.EACCES)
    filt.kill("ptrace")
    filt.load()

The compiled program first rejects foreign ABIs by comparing
seccomp_data.arch against the native AUDIT_ARCH_* value, then
dispatches on the syscall number. Loading is irreversible and requires
either CAP_SYS_ADMIN or no_new_privs; load() sets no_new_privs itself.

Kernel reference: https://docs.kernel.org/userspace-api/seccomp_filter.html
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import IntEnum, IntFlag
from typing import Final

from . import _syscall, bpf
from .syscalls import audit_arch, syscall_nr

__all__ = ["Action", "Filter", "FilterFlag"]

SECCOMP_RET_DATA: Final = 0x0000FFFF
"""Mask for the per-syscall data bits carried by ERRNO and TRACE."""

_OFF_NR: Final = 0
_OFF_ARCH: Final = 4
_OFF_ARG0: Final = 16


class Action(IntEnum):
    """Seccomp return actions, mirroring SECCOMP_RET_*.

    ERRNO and TRACE carry a 16-bit payload in the low bits; the Filter
    methods errno() and trace() attach it. KILL is the classic alias for
    KILL_THREAD.
    """

    KILL_PROCESS = 0x80000000
    KILL_THREAD = 0x00000000
    KILL = 0x00000000
    TRAP = 0x00030000
    ERRNO = 0x00050000
    TRACE = 0x7FF00000
    LOG = 0x7FFC0000
    ALLOW = 0x7FFF0000


class FilterFlag(IntFlag):
    """Flags accepted by SECCOMP_SET_MODE_FILTER, mirroring
    SECCOMP_FILTER_FLAG_*. NEW_LISTENER is probed but rejected by
    load(), since the notification protocol is not implemented.
    """

    NONE = 0
    TSYNC = 1 << 0
    LOG = 1 << 1
    SPEC_ALLOW = 1 << 2
    NEW_LISTENER = 1 << 3
    TSYNC_ESRCH = 1 << 4
    WAIT_KILLABLE_RECV = 1 << 5


@dataclass(frozen=True)
class _Rule:
    action: int
    args: tuple[tuple[int, int], ...]


class Filter:
    """A seccomp-BPF filter under construction.

    The default action applies to every syscall that has no matching
    rule. Rules are added with the action methods and match on the
    syscall number, plus optionally on equality of one or more 64-bit
    arguments. Rules for the same syscall are evaluated in insertion
    order and the first match wins.

    Loading installs the filter on the calling thread and is
    irreversible; children inherit it. The filter refuses mutation once
    loaded and cannot be copied.

    Kernel reference: https://docs.kernel.org/userspace-api/seccomp_filter.html
    """

    __slots__ = ("_default", "_flags", "_loaded", "_program", "_rules")

    def __init__(
        self,
        default: Action | int = Action.ALLOW,
        *,
        flags: FilterFlag = FilterFlag.NONE,
    ) -> None:
        default = int(default)
        if not 0 <= default <= 0xFFFFFFFF:
            raise ValueError(f"default action out of range: {default:#x}")
        self._default = default
        self._flags = FilterFlag(flags)
        self._rules: dict[int, list[_Rule]] = {}
        self._program: bytes | None = None
        self._loaded = False

    def _check_mutable(self) -> None:
        if self._loaded:
            raise RuntimeError("filter is already loaded")

    def _add(
        self,
        syscall: str | int,
        action: int,
        args: Mapping[int, int] | None = None,
    ) -> None:
        self._check_mutable()
        nr = syscall_nr(syscall)
        conds: tuple[tuple[int, int], ...] = ()
        if args:
            for index, value in sorted(args.items()):
                if not 0 <= index <= 5:
                    raise ValueError(f"argument index out of range: {index}")
                if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
                    raise ValueError(f"argument value out of range: {value:#x}")
                conds += ((index, value),)
        self._rules.setdefault(nr, []).append(_Rule(action, conds))
        self._program = None

    def allow(
        self, syscall: str | int, *, args: Mapping[int, int] | None = None
    ) -> None:
        """Allow a syscall, optionally only when the given args match."""
        self._add(syscall, int(Action.ALLOW), args)

    def kill(
        self, syscall: str | int, *, args: Mapping[int, int] | None = None
    ) -> None:
        """Kill the whole process when it invokes the syscall."""
        self._add(syscall, int(Action.KILL_PROCESS), args)

    def kill_thread(
        self, syscall: str | int, *, args: Mapping[int, int] | None = None
    ) -> None:
        """Kill only the calling thread (the classic KILL action)."""
        self._add(syscall, int(Action.KILL_THREAD), args)

    def trap(
        self, syscall: str | int, *, args: Mapping[int, int] | None = None
    ) -> None:
        """Deliver SIGSYS to the thread when it invokes the syscall."""
        self._add(syscall, int(Action.TRAP), args)

    def errno(
        self,
        syscall: str | int,
        error: int,
        *,
        args: Mapping[int, int] | None = None,
    ) -> None:
        """Make the syscall fail with the given errno value."""
        if not 0 <= error <= SECCOMP_RET_DATA:
            raise ValueError(f"errno out of range: {error}")
        self._add(syscall, int(Action.ERRNO) | error, args)

    def trace(
        self,
        syscall: str | int,
        msg: int = 0,
        *,
        args: Mapping[int, int] | None = None,
    ) -> None:
        """Hand the syscall to a ptrace tracer, tagging it with msg."""
        if not 0 <= msg <= SECCOMP_RET_DATA:
            raise ValueError(f"trace message out of range: {msg}")
        self._add(syscall, int(Action.TRACE) | msg, args)

    def log(self, syscall: str | int, *, args: Mapping[int, int] | None = None) -> None:
        """Allow the syscall but log it where the kernel sends audit."""
        self._add(syscall, int(Action.LOG), args)

    @property
    def default(self) -> int:
        """The return value applied to syscalls without a matching rule."""
        return self._default

    @property
    def flags(self) -> FilterFlag:
        """The flags passed to SECCOMP_SET_MODE_FILTER by load()."""
        return self._flags

    @property
    def loaded(self) -> bool:
        """Whether load() has been called successfully."""
        return self._loaded

    @property
    def program(self) -> bytes:
        """The compiled BPF program as packed sock_filter bytes."""
        if self._program is None:
            self._program = self._compile()
        return self._program

    def _compile(self) -> bytes:
        insns: list[bpf.Insn] = [
            bpf.Load(_OFF_ARCH),
            bpf.Jump(bpf.BPF_JEQ, audit_arch(), None, "kill"),
            bpf.Load(_OFF_NR),
        ]
        labels: dict[str, int] = {}
        insns.extend(
            bpf.Jump(bpf.BPF_JEQ, nr & 0xFFFFFFFF, f"block_{nr}", None)
            for nr in self._rules
        )
        insns.append(bpf.Ret(self._default))

        for nr, rules in self._rules.items():
            labels[f"block_{nr}"] = len(insns)
            falls_through = True
            for i, rule in enumerate(rules):
                if not rule.args:
                    insns.append(bpf.Ret(rule.action))
                    falls_through = False
                    break
                nxt = f"next_{nr}_{i}"
                for index, value in rule.args:
                    lo = value & 0xFFFFFFFF
                    hi = (value >> 32) & 0xFFFFFFFF
                    insns.append(bpf.Load(_OFF_ARG0 + 8 * index))
                    insns.append(bpf.Jump(bpf.BPF_JEQ, lo, None, nxt))
                    insns.append(bpf.Load(_OFF_ARG0 + 8 * index + 4))
                    insns.append(bpf.Jump(bpf.BPF_JEQ, hi, None, nxt))
                insns.append(bpf.Ret(rule.action))
                labels[nxt] = len(insns)
            if falls_through:
                insns.append(bpf.Ret(self._default))

        labels["kill"] = len(insns)
        insns.append(bpf.Ret(int(Action.KILL_PROCESS)))
        return bpf.assemble(insns, labels)

    def load(self) -> None:
        """Install the filter on the calling thread via seccomp(2).

        Sets no_new_privs first, so unprivileged callers can load. The
        kernel rejects unknown flags with EINVAL; probe them beforehand
        with seccompy.flag_supported(). NEW_LISTENER is not supported by
        this library and is rejected with ValueError.
        """
        if self._loaded:
            raise RuntimeError("filter is already loaded")
        if self._flags & FilterFlag.NEW_LISTENER:
            raise ValueError("NEW_LISTENER requires the user notification protocol")
        _syscall.set_no_new_privs()
        _syscall.set_mode_filter(self.program, int(self._flags))
        self._loaded = True

    def __copy__(self) -> Filter:
        raise TypeError("Filter cannot be copied; clone its rules instead")

    def __deepcopy__(self, memo: dict[int, object]) -> Filter:
        raise TypeError("Filter cannot be copied; clone its rules instead")

    def __repr__(self) -> str:
        state = "loaded" if self._loaded else "building"
        return (
            f"{type(self).__name__}(default={self._default:#x}, "
            f"rules={sum(len(r) for r in self._rules.values())}, {state})"
        )
