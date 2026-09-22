# SPDX-License-Identifier: 0BSD
"""Classic BPF instruction model and assembler for seccomp filters.

A seccomp filter is a classic BPF program run over struct seccomp_data.
This module lets callers describe programs as instruction objects with
symbolic jump labels; assemble() resolves the labels into the 8-bit
relative offsets struct sock_filter requires. Classic BPF only jumps
forward, and conditional jumps are limited to 255 instructions, so a
conditional jump whose target lies farther away is expanded into a short
conditional hop over an unconditional 32-bit JA.

The result is packed as little-endian struct sock_filter records of
8 bytes each: u16 code, u8 jt, u8 jf, u32 k.

Kernel reference: https://docs.kernel.org/userspace-api/seccomp_filter.html
"""

import struct
from dataclasses import dataclass
from typing import Final

__all__ = [
    "BPF_JA",
    "BPF_JEQ",
    "BPF_JGEQ",
    "BPF_JGT",
    "BPF_JSET",
    "BPF_LD_ABS_W",
    "BPF_RET_K",
    "Insn",
    "Ja",
    "Jump",
    "Load",
    "Ret",
    "assemble",
]

BPF_LD_ABS_W: Final = 0x20
"""BPF_LD | BPF_W | BPF_ABS: load the 32-bit word at byte offset k."""

BPF_RET_K: Final = 0x06
"""BPF_RET | BPF_K: terminate the program with result k."""

BPF_JA: Final = 0x05
"""BPF_JMP | BPF_JA: unconditional jump forward by k instructions."""

BPF_JEQ: Final = 0x15
"""BPF_JMP | BPF_JEQ | BPF_K: jump if A equals k."""

BPF_JGT: Final = 0x25
"""BPF_JMP | BPF_JGT | BPF_K: jump if A is greater than k."""

BPF_JGEQ: Final = 0x35
"""BPF_JMP | BPF_JGEQ | BPF_K: jump if A is greater than or equal to k."""

BPF_JSET: Final = 0x45
"""BPF_JMP | BPF_JSET | BPF_K: jump if A has any bit of k set."""

_JUMP_OPS: Final = frozenset({BPF_JEQ, BPF_JGT, BPF_JGEQ, BPF_JSET})

_MAX_COND_JUMP: Final = 255


class Insn:
    """Base class for BPF instructions."""

    __slots__ = ()


@dataclass(frozen=True)
class Load(Insn):
    """Load the 32-bit word at byte offset k of the packet data."""

    k: int


@dataclass(frozen=True)
class Jump(Insn):
    """Compare A against k and jump to the jt or jf label.

    A label of None means fall through to the next instruction.
    """

    op: int
    k: int
    jt: str | None = None
    jf: str | None = None

    def __post_init__(self) -> None:
        if self.op not in _JUMP_OPS:
            raise ValueError(f"not a conditional jump opcode: {self.op:#x}")


@dataclass(frozen=True)
class Ja(Insn):
    """Jump unconditionally to a label."""

    target: str


@dataclass(frozen=True)
class Ret(Insn):
    """Terminate the program with result k."""

    k: int


def _positions(sizes: list[int]) -> list[int]:
    """Instruction start positions plus the position past the end."""
    pos = [0] * (len(sizes) + 1)
    for i in range(1, len(sizes) + 1):
        pos[i] = pos[i - 1] + sizes[i - 1]
    return pos


def _expanded_size(jump: Jump) -> int:
    if jump.jt is None:
        return 2
    return 3 if jump.jf is not None else 2


def assemble(insns: list[Insn], labels: dict[str, int]) -> bytes:
    """Resolve labels and pack insns into struct sock_filter bytes.

    labels maps each symbolic name to an instruction index, which may be
    len(insns) to name the position just past the last instruction.
    Raises ValueError for unknown labels, backward jumps or jumps that
    still cannot be encoded.
    """
    _validate_labels(insns, labels)
    sizes = _resolve_sizes(insns, labels)
    pos = _positions(sizes)
    out = bytearray()
    for i, insn in enumerate(insns):
        out += _emit(insn, labels, pos, i, sizes[i])
    return bytes(out)


def _validate_labels(insns: list[Insn], labels: dict[str, int]) -> None:
    for insn in insns:
        for target in _targets(insn):
            if target not in labels:
                raise ValueError(f"undefined label: {target}")
            if labels[target] > len(insns):
                raise ValueError(f"label out of range: {target}")


def _resolve_sizes(insns: list[Insn], labels: dict[str, int]) -> list[int]:
    """Size each instruction, expanding conditional jumps that resolve
    to offsets beyond 255 into a hop plus JA trampolines. Expansion
    only grows programs, so iterating to a fixed point terminates."""
    sizes = [1] * len(insns)
    for _ in range(len(insns) + 1):
        pos = _positions(sizes)
        changed = False
        for i, insn in enumerate(insns):
            if not isinstance(insn, Jump) or sizes[i] > 1:
                continue
            if _needs_expansion(insn, labels, pos, i):
                sizes[i] = _expanded_size(insn)
                changed = True
        if not changed:
            return sizes
    raise ValueError("jump resolution did not converge")


def _targets(insn: Insn) -> list[str]:
    if isinstance(insn, Jump):
        return [t for t in (insn.jt, insn.jf) if t is not None]
    if isinstance(insn, Ja):
        return [insn.target]
    return []


def _offset(
    target: str | None, labels: dict[str, int], pos: list[int], i: int
) -> int | None:
    if target is None:
        return None
    off = pos[labels[target]] - pos[i] - 1
    if off < 0:
        raise ValueError(f"backward jump to label: {target}")
    return off


def _needs_expansion(
    jump: Jump, labels: dict[str, int], pos: list[int], i: int
) -> bool:
    for target in (jump.jt, jump.jf):
        off = _offset(target, labels, pos, i)
        if off is not None and off > _MAX_COND_JUMP:
            return True
    return False


def _emit(
    insn: Insn, labels: dict[str, int], pos: list[int], i: int, size: int
) -> bytes:
    if isinstance(insn, Load):
        return struct.pack("<HBBI", BPF_LD_ABS_W, 0, 0, insn.k)
    if isinstance(insn, Ja):
        off = _offset(insn.target, labels, pos, i)
        if off is None or off > 0xFFFFFFFF:
            raise ValueError(f"JA target out of range: {insn.target}")
        return struct.pack("<HBBI", BPF_JA, 0, 0, off)
    if isinstance(insn, Ret):
        return struct.pack("<HBBI", BPF_RET_K, 0, 0, insn.k)
    if isinstance(insn, Jump):
        jt = _offset(insn.jt, labels, pos, i)
        jf = _offset(insn.jf, labels, pos, i)
        if size == 1:
            if (jt is not None and jt > _MAX_COND_JUMP) or (
                jf is not None and jf > _MAX_COND_JUMP
            ):
                raise ValueError("conditional jump out of range")
            return struct.pack("<HBBI", insn.op, jt or 0, jf or 0, insn.k)
        return _emit_expanded(insn, labels, pos, i)
    raise TypeError(f"unknown instruction: {insn!r}")


def _emit_expanded(jump: Jump, labels: dict[str, int], pos: list[int], i: int) -> bytes:
    """Encode a far conditional jump as a hop plus JA trampolines.

    jt None:  jXX jt=1 jf=0; JA jf   (true falls past the JA)
    jf None:  jXX jt=0 jf=1; JA jt   (false falls past the JA)
    both:     jXX jt=0 jf=1; JA jt; JA jf
    """
    out = bytearray()
    if jump.jt is None:
        out += struct.pack("<HBBI", jump.op, 1, 0, jump.k)
        out += _ja_bytes(jump.jf, labels, pos, pos[i] + 1)
    else:
        out += struct.pack("<HBBI", jump.op, 0, 1, jump.k)
        out += _ja_bytes(jump.jt, labels, pos, pos[i] + 1)
        if jump.jf is not None:
            out += _ja_bytes(jump.jf, labels, pos, pos[i] + 2)
    return bytes(out)


def _ja_bytes(
    target: str | None, labels: dict[str, int], pos: list[int], pc: int
) -> bytes:
    if target is None:
        raise ValueError("JA without a target")
    off = pos[labels[target]] - pc - 1
    if off < 0 or off > 0xFFFFFFFF:
        raise ValueError(f"JA target out of range: {target}")
    return struct.pack("<HBBI", BPF_JA, 0, 0, off)
