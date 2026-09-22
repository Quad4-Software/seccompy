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

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import IntEnum, IntFlag
from typing import Final, cast

from . import _syscall, bpf
from .notify import Listener
from .syscalls import audit_arch, syscall_nr

__all__ = [
    "Action",
    "ArgCmp",
    "ArgCond",
    "Args",
    "CmpOp",
    "Filter",
    "FilterFlag",
]

SECCOMP_RET_DATA: Final = 0x0000FFFF
"""Mask for the per-syscall data bits carried by ERRNO and TRACE."""

_OFF_NR: Final = 0
_OFF_ARCH: Final = 4
_OFF_ARG0: Final = 16

_U64: Final = 0xFFFFFFFFFFFFFFFF


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
    USER_NOTIF = 0x7FC00000
    TRACE = 0x7FF00000
    LOG = 0x7FFC0000
    ALLOW = 0x7FFF0000


class FilterFlag(IntFlag):
    """Flags accepted by SECCOMP_SET_MODE_FILTER, mirroring
    SECCOMP_FILTER_FLAG_*. With NEW_LISTENER, load() returns a
    notify.Listener for the SECCOMP_RET_USER_NOTIF protocol.
    """

    NONE = 0
    TSYNC = 1 << 0
    LOG = 1 << 1
    SPEC_ALLOW = 1 << 2
    NEW_LISTENER = 1 << 3
    TSYNC_ESRCH = 1 << 4
    WAIT_KILLABLE_RECV = 1 << 5


class CmpOp(IntEnum):
    """Argument comparison operators, mirroring SCMP_CMP_*.

    All comparisons are unsigned and apply to the full 64-bit argument
    value. MASKED_EQ tests arg & mask == value, which is the only way to
    match flag bits like O_RDONLY whose value is zero.
    """

    EQ = 0
    NE = 1
    LT = 2
    LE = 3
    GT = 4
    GE = 5
    MASKED_EQ = 6


@dataclass(frozen=True)
class ArgCmp:
    """One condition on a 64-bit syscall argument.

    Compares seccomp_data.args[index] against value using op. mask is
    only meaningful for MASKED_EQ, where it selects the bits compared;
    value must not have bits set outside mask.
    """

    index: int
    op: CmpOp
    value: int
    mask: int = _U64

    def __post_init__(self) -> None:
        object.__setattr__(self, "op", CmpOp(self.op))
        if not 0 <= self.index <= 5:
            raise ValueError(f"argument index out of range: {self.index}")
        if not 0 <= self.value <= _U64:
            raise ValueError(f"argument value out of range: {self.value:#x}")
        if not 0 <= self.mask <= _U64:
            raise ValueError(f"argument mask out of range: {self.mask:#x}")
        if self.op is CmpOp.MASKED_EQ:
            if self.value & ~self.mask:
                raise ValueError("masked-eq value has bits outside the mask")
        elif self.mask != _U64:
            raise ValueError("mask is only meaningful with MASKED_EQ")


ArgCond = ArgCmp | tuple[int, int, int] | tuple[int, int, int, int]
"""One arg condition: an ArgCmp or an (index, op, value[, mask]) tuple."""

Args = Mapping[int, int] | Iterable[ArgCond]
"""Arg conditions for a rule: an index->value equality mapping or an
iterable of ArgCmp / (index, op, value[, mask]) tuples."""


def _coerce_cond(cond: ArgCond) -> ArgCmp:
    if isinstance(cond, ArgCmp):
        return cond
    if len(cond) == 3:
        index, op, value = cond
        return ArgCmp(index, CmpOp(op), value)
    index, op, value, mask = cond
    return ArgCmp(index, CmpOp(op), value, mask)


@dataclass(frozen=True)
class _Rule:
    action: int
    args: tuple[ArgCmp, ...]


class Filter:
    """A seccomp-BPF filter under construction.

    The default action applies to every syscall that has no matching
    rule. Rules are added with the action methods and match on the
    syscall number, plus optionally on conditions on the 64-bit
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
        args: Args | None = None,
    ) -> None:
        self._check_mutable()
        nr = syscall_nr(syscall)
        conds: tuple[ArgCmp, ...] = ()
        if args:
            if isinstance(args, Mapping):
                mapping = cast("Mapping[int, int]", args)
                raw = (
                    ArgCmp(index, CmpOp.EQ, value) for index, value in mapping.items()
                )
            else:
                raw = (_coerce_cond(cond) for cond in args)
            conds = tuple(sorted(raw, key=lambda cond: cond.index))
        self._rules.setdefault(nr, []).append(_Rule(action, conds))
        self._program = None

    def allow(self, syscall: str | int, *, args: Args | None = None) -> None:
        """Allow a syscall, optionally only when the given args match."""
        self._add(syscall, int(Action.ALLOW), args)

    def kill(self, syscall: str | int, *, args: Args | None = None) -> None:
        """Kill the whole process when it invokes the syscall."""
        self._add(syscall, int(Action.KILL_PROCESS), args)

    def kill_thread(self, syscall: str | int, *, args: Args | None = None) -> None:
        """Kill only the calling thread (the classic KILL action)."""
        self._add(syscall, int(Action.KILL_THREAD), args)

    def trap(self, syscall: str | int, *, args: Args | None = None) -> None:
        """Deliver SIGSYS to the thread when it invokes the syscall."""
        self._add(syscall, int(Action.TRAP), args)

    def errno(
        self, syscall: str | int, error: int, *, args: Args | None = None
    ) -> None:
        """Make the syscall fail with the given errno value."""
        if not 0 <= error <= SECCOMP_RET_DATA:
            raise ValueError(f"errno out of range: {error}")
        self._add(syscall, int(Action.ERRNO) | error, args)

    def trace(
        self, syscall: str | int, msg: int = 0, *, args: Args | None = None
    ) -> None:
        """Hand the syscall to a ptrace tracer, tagging it with msg."""
        if not 0 <= msg <= SECCOMP_RET_DATA:
            raise ValueError(f"trace message out of range: {msg}")
        self._add(syscall, int(Action.TRACE) | msg, args)

    def log(self, syscall: str | int, *, args: Args | None = None) -> None:
        """Allow the syscall but log it where the kernel sends audit."""
        self._add(syscall, int(Action.LOG), args)

    def notify(self, syscall: str | int, *, args: Args | None = None) -> None:
        """Send the syscall to a user-space supervisor for handling.

        Requires the filter to be loaded with FilterFlag.NEW_LISTENER;
        each matching syscall queues a notification on the listener fd
        and blocks until the supervisor responds. See seccompy.notify.
        """
        self._add(syscall, int(Action.USER_NOTIF), args)

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
                for j, cond in enumerate(rule.args):
                    _emit_cond(insns, labels, cond, nxt, f"hit_{nr}_{i}_{j}")
                insns.append(bpf.Ret(rule.action))
                labels[nxt] = len(insns)
            if falls_through:
                insns.append(bpf.Ret(self._default))

        labels["kill"] = len(insns)
        insns.append(bpf.Ret(int(Action.KILL_PROCESS)))
        return bpf.assemble(insns, labels)

    def load(self) -> Listener | None:
        """Install the filter on the calling thread via seccomp(2).

        Sets no_new_privs first, so unprivileged callers can load. The
        kernel rejects unknown flags with EINVAL; probe them beforehand
        with seccompy.flag_supported(). With FilterFlag.NEW_LISTENER the
        return value is a notify.Listener for the user notification
        protocol; otherwise it is None.
        """
        if self._loaded:
            raise RuntimeError("filter is already loaded")
        _syscall.set_no_new_privs()
        ret = _syscall.set_mode_filter(self.program, int(self._flags))
        self._loaded = True
        if self._flags & FilterFlag.NEW_LISTENER:
            return Listener(ret)
        return None

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


def _emit_cond(
    insns: list[bpf.Insn],
    labels: dict[str, int],
    cond: ArgCmp,
    fail: str,
    passed: str,
) -> None:
    """Emit the instruction sequence for one argument condition.

    Classic BPF compares 32-bit words while seccomp_data args are 64
    bits, so ordered comparisons test the high word first and only fall
    back to the low word on equality. A jump to fail means the
    condition does not hold; the passed label marks the position right
    after the sequence, reached when the condition holds.
    """
    lo_off = _OFF_ARG0 + 8 * cond.index
    hi_off = lo_off + 4
    lo = cond.value & 0xFFFFFFFF
    hi = (cond.value >> 32) & 0xFFFFFFFF

    if cond.op is CmpOp.EQ:
        insns.append(bpf.Load(lo_off))
        insns.append(bpf.Jump(bpf.BPF_JEQ, lo, None, fail))
        insns.append(bpf.Load(hi_off))
        insns.append(bpf.Jump(bpf.BPF_JEQ, hi, None, fail))
    elif cond.op is CmpOp.NE:
        insns.append(bpf.Load(lo_off))
        insns.append(bpf.Jump(bpf.BPF_JEQ, lo, None, passed))
        insns.append(bpf.Load(hi_off))
        insns.append(bpf.Jump(bpf.BPF_JEQ, hi, fail, None))
    elif cond.op in (CmpOp.LT, CmpOp.LE):
        insns.append(bpf.Load(hi_off))
        insns.append(bpf.Jump(bpf.BPF_JGT, hi, fail, None))
        insns.append(bpf.Jump(bpf.BPF_JEQ, hi, None, passed))
        insns.append(bpf.Load(lo_off))
        jop = bpf.BPF_JGEQ if cond.op is CmpOp.LT else bpf.BPF_JGT
        insns.append(bpf.Jump(jop, lo, fail, None))
    elif cond.op in (CmpOp.GT, CmpOp.GE):
        insns.append(bpf.Load(hi_off))
        insns.append(bpf.Jump(bpf.BPF_JGT, hi, passed, None))
        insns.append(bpf.Jump(bpf.BPF_JEQ, hi, None, fail))
        insns.append(bpf.Load(lo_off))
        jop = bpf.BPF_JGT if cond.op is CmpOp.GT else bpf.BPF_JGEQ
        insns.append(bpf.Jump(jop, lo, passed, fail))
    else:  # CmpOp.MASKED_EQ: (arg & mask) == value, per 32-bit word
        mlo = cond.mask & 0xFFFFFFFF
        mhi = (cond.mask >> 32) & 0xFFFFFFFF
        for off, m, v in ((lo_off, mlo, lo), (hi_off, mhi, hi)):
            if m == 0:
                continue
            insns.append(bpf.Load(off))
            insns.append(bpf.And(m))
            insns.append(bpf.Jump(bpf.BPF_JEQ, v, None, fail))
    labels[passed] = len(insns)
