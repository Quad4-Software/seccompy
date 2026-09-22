# SPDX-License-Identifier: 0BSD
"""Tests for argument comparison operators and their BPF codegen."""

import errno
import struct
from typing import cast

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from seccompy import Action, ArgCmp, CmpOp, Filter
from seccompy.bpf import (
    BPF_ALU_AND_K,
    BPF_JEQ,
    BPF_JGT,
    BPF_LD_ABS_W,
    BPF_RET_K,
)
from seccompy.syscalls import audit_arch, syscall_nr

from .test_bpf import pack, run_packed

ERR = int(Action.ERRNO) | errno.EIO
ALW = int(Action.ALLOW)
KILL = int(Action.KILL_PROCESS)
WRITE_NR = syscall_nr("write")
OPENAT_NR = syscall_nr("openat")


def insns(prog: bytes) -> list[tuple[int, int, int, int]]:
    return [struct.unpack_from("<HBBI", prog, i * 8) for i in range(len(prog) // 8)]


def data_for(nr: int, *args: int) -> bytes:
    """Build a synthetic seccomp_data for the native arch."""
    data = bytearray(64)
    struct.pack_into("<i", data, 0, nr)
    struct.pack_into("<I", data, 4, audit_arch())
    for i, arg in enumerate(args):
        struct.pack_into("<Q", data, 16 + 8 * i, arg)
    return bytes(data)


def run_rule(op: CmpOp, value: int, arg: int, mask: int = 0xFFFFFFFFFFFFFFFF) -> int:
    """Run a one-rule filter over a single arg0 value."""
    filt = Filter(default=Action.ALLOW)
    filt.errno("write", errno.EIO, args=[ArgCmp(0, op, value, mask)])
    return run_packed(filt.program, data_for(WRITE_NR, arg))


def test_cmpop_values() -> None:
    assert [int(op) for op in CmpOp] == [0, 1, 2, 3, 4, 5, 6]


def test_argcmp_coerces_int_op() -> None:
    # A plain int is coerced to CmpOp at runtime; cast keeps the
    # intentional loose call legible to type checkers.
    assert ArgCmp(0, cast("CmpOp", 4), 7).op is CmpOp.GT


def test_argcmp_validation() -> None:
    with pytest.raises(ValueError, match="index"):
        ArgCmp(6, CmpOp.EQ, 0)
    with pytest.raises(ValueError, match="value"):
        ArgCmp(0, CmpOp.EQ, 1 << 64)
    with pytest.raises(ValueError, match="mask"):
        ArgCmp(0, CmpOp.MASKED_EQ, 0, mask=-1)
    with pytest.raises(ValueError, match="outside the mask"):
        ArgCmp(0, CmpOp.MASKED_EQ, 8, mask=3)
    with pytest.raises(ValueError, match="only meaningful"):
        ArgCmp(0, CmpOp.GT, 0, mask=0xFF)


def test_gt_golden_program() -> None:
    filt = Filter(default=Action.ALLOW)
    filt.errno("write", errno.EIO, args=[ArgCmp(0, CmpOp.GT, 0x1_0000_0000)])
    assert insns(filt.program) == [
        (BPF_LD_ABS_W, 0, 0, 4),
        (BPF_JEQ, 0, 10, audit_arch()),
        (BPF_LD_ABS_W, 0, 0, 0),
        (BPF_JEQ, 1, 0, WRITE_NR),
        (BPF_RET_K, 0, 0, ALW),
        (BPF_LD_ABS_W, 0, 0, 20),  # arg0 high word
        (BPF_JGT, 3, 0, 1),  # hi > 1 -> hit
        (BPF_JEQ, 0, 3, 1),  # hi == 1 -> check lo; hi < 1 -> next rule
        (BPF_LD_ABS_W, 0, 0, 16),  # arg0 low word
        (BPF_JGT, 0, 1, 0),  # lo > 0 -> hit; else next rule
        (BPF_RET_K, 0, 0, ERR),
        (BPF_RET_K, 0, 0, ALW),
        (BPF_RET_K, 0, 0, KILL),
    ]


def test_masked_eq_golden_program() -> None:
    # arg1 & O_ACCMODE == O_RDONLY: mask 3, value 0, hi word vacuous.
    filt = Filter(default=Action.ALLOW)
    filt.errno("openat", errno.EIO, args=[ArgCmp(1, CmpOp.MASKED_EQ, 0, mask=3)])
    assert insns(filt.program) == [
        (BPF_LD_ABS_W, 0, 0, 4),
        (BPF_JEQ, 0, 8, audit_arch()),
        (BPF_LD_ABS_W, 0, 0, 0),
        (BPF_JEQ, 1, 0, OPENAT_NR),
        (BPF_RET_K, 0, 0, ALW),
        (BPF_LD_ABS_W, 0, 0, 24),  # arg1 low word
        (BPF_ALU_AND_K, 0, 0, 3),
        (BPF_JEQ, 0, 1, 0),
        (BPF_RET_K, 0, 0, ERR),
        (BPF_RET_K, 0, 0, ALW),
        (BPF_RET_K, 0, 0, KILL),
    ]
    assert filt.program == (
        pack(BPF_LD_ABS_W, 0, 0, 4)
        + pack(BPF_JEQ, 0, 8, audit_arch())
        + pack(BPF_LD_ABS_W, 0, 0, 0)
        + pack(BPF_JEQ, 1, 0, OPENAT_NR)
        + pack(BPF_RET_K, 0, 0, ALW)
        + pack(BPF_LD_ABS_W, 0, 0, 24)
        + pack(BPF_ALU_AND_K, 0, 0, 3)
        + pack(BPF_JEQ, 0, 1, 0)
        + pack(BPF_RET_K, 0, 0, ERR)
        + pack(BPF_RET_K, 0, 0, ALW)
        + pack(BPF_RET_K, 0, 0, KILL)
    )


def test_masked_eq_both_words() -> None:
    filt = Filter(default=Action.ALLOW)
    filt.errno(
        "write",
        errno.EIO,
        args=[ArgCmp(0, CmpOp.MASKED_EQ, 0xABCD_0000_0000, mask=0xFFFF_FFFF_0000_0000)],
    )
    prog = insns(filt.program)
    # lo word: (lo & 0) == 0 is vacuous and skipped; hi word is checked.
    assert prog[5:8] == [
        (BPF_LD_ABS_W, 0, 0, 20),
        (BPF_ALU_AND_K, 0, 0, 0xFFFFFFFF),
        (BPF_JEQ, 0, 1, 0xABCD),
    ]
    assert prog[8] == (BPF_RET_K, 0, 0, ERR)


@given(
    value=st.integers(0, 0xFFFFFFFFFFFFFFFF),
    arg=st.integers(0, 0xFFFFFFFFFFFFFFFF),
)
@settings(max_examples=800)
def test_ops_match_unsigned_semantics(value: int, arg: int) -> None:
    assert (run_rule(CmpOp.EQ, value, arg) == ERR) == (arg == value)
    assert (run_rule(CmpOp.NE, value, arg) == ERR) == (arg != value)
    assert (run_rule(CmpOp.LT, value, arg) == ERR) == (arg < value)
    assert (run_rule(CmpOp.LE, value, arg) == ERR) == (arg <= value)
    assert (run_rule(CmpOp.GT, value, arg) == ERR) == (arg > value)
    assert (run_rule(CmpOp.GE, value, arg) == ERR) == (arg >= value)


@given(
    mask=st.integers(0, 0xFFFFFFFFFFFFFFFF),
    arg=st.integers(0, 0xFFFFFFFFFFFFFFFF),
    extra=st.integers(0, 0xFFFFFFFFFFFFFFFF),
)
@settings(max_examples=500)
def test_masked_eq_matches_masked_bits(mask: int, arg: int, extra: int) -> None:
    value = arg & mask
    assert run_rule(CmpOp.MASKED_EQ, value, arg, mask) == ERR
    # A different value inside the mask must not match.
    other = value ^ extra
    if other & ~mask == 0 and other != value:
        assert run_rule(CmpOp.MASKED_EQ, other, arg, mask) == ALW


def test_gt_boundary_words() -> None:
    # High word decides before the low word is compared.
    assert run_rule(CmpOp.GT, 0xFFFF_FFFF, 0x1_0000_0000) == ERR
    assert run_rule(CmpOp.GT, 0x1_0000_0000, 0xFFFF_FFFF) == ALW
    assert run_rule(CmpOp.LT, 0x1_0000_0000, 0xFFFF_FFFF) == ERR
    assert run_rule(CmpOp.GE, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF) == ERR
    assert run_rule(CmpOp.LT, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFE) == ERR
    assert run_rule(CmpOp.NE, 0x1_0000_0000, 0x0_0000_0001) == ERR  # differs in hi
    assert run_rule(CmpOp.NE, 0x1_0000_0000, 0x1_0000_0001) == ERR  # differs in lo


def test_masked_eq_flag_bits() -> None:
    # The O_RDONLY motivation: arg & O_ACCMODE == 0, with noise above it.
    assert run_rule(CmpOp.MASKED_EQ, 0, 0, mask=3) == ERR
    assert run_rule(CmpOp.MASKED_EQ, 0, 1 << 40, mask=3) == ERR
    assert run_rule(CmpOp.MASKED_EQ, 0, 2, mask=3) == ALW
    assert run_rule(CmpOp.MASKED_EQ, 2, 0x102, mask=3) == ERR


def test_multiple_conditions_and_together() -> None:
    filt = Filter(default=Action.ALLOW)
    filt.errno(
        "write",
        errno.EIO,
        args=[ArgCmp(0, CmpOp.GT, 5), ArgCmp(0, CmpOp.LT, 100)],
    )
    for arg, hit in [(5, False), (6, True), (99, True), (100, False), (200, False)]:
        got = run_packed(filt.program, data_for(WRITE_NR, arg))
        assert (got == ERR) == hit, arg


def test_multiple_indexes() -> None:
    filt = Filter(default=Action.ALLOW)
    filt.errno(
        "openat",
        errno.EIO,
        args=[ArgCmp(0, CmpOp.EQ, 0xFFFFFF9C), ArgCmp(2, CmpOp.NE, 0)],
    )
    hit = run_packed(filt.program, data_for(OPENAT_NR, 0xFFFFFF9C, 0xAAAA, 0o644))
    assert hit == ERR
    miss = run_packed(filt.program, data_for(OPENAT_NR, 0xFFFFFF9C, 0xAAAA, 0))
    assert miss == ALW


def test_tuple_conditions_accepted() -> None:
    filt = Filter(default=Action.ALLOW)
    filt.errno("write", errno.EIO, args=[(0, CmpOp.GT, 10), (1, CmpOp.MASKED_EQ, 0, 3)])
    hit = run_packed(filt.program, data_for(WRITE_NR, 11, 4))
    assert hit == ERR
    miss = run_packed(filt.program, data_for(WRITE_NR, 11, 5))
    assert miss == ALW


def test_mapping_still_equality() -> None:
    filt = Filter(default=Action.ALLOW)
    filt.errno("write", errno.EIO, args={0: 0x1_2345_6789})
    hit = run_packed(filt.program, data_for(WRITE_NR, 0x1_2345_6789))
    assert hit == ERR
    miss = run_packed(filt.program, data_for(WRITE_NR, 0x1_2345_678A))
    assert miss == ALW


def test_bad_tuple_condition() -> None:
    filt = Filter(default=Action.ALLOW)
    with pytest.raises(ValueError, match="index"):
        filt.errno("write", errno.EIO, args=[(9, CmpOp.EQ, 0)])
    with pytest.raises(ValueError, match="CmpOp"):
        filt.errno("write", errno.EIO, args=[(0, 99, 0)])  # bad op number


def test_conditions_apply_to_notify_action() -> None:
    filt = Filter(default=Action.ALLOW)
    filt.notify("openat", args=[ArgCmp(2, CmpOp.EQ, 0)])
    got = run_packed(filt.program, data_for(OPENAT_NR, 0, 0, 0))
    assert got == int(Action.USER_NOTIF)
