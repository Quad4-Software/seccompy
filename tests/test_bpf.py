# SPDX-License-Identifier: 0BSD
"""Tests for the classic BPF instruction model and assembler."""

import struct

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from seccompy import bpf

KILL_PROCESS = 0x80000000
ALLOW = 0x7FFF0000
AUDIT_ARCH_X86_64 = 0xC000003E


def pack(code: int, jt: int, jf: int, k: int) -> bytes:
    return struct.pack("<HBBI", code, jt, jf, k)


def run_packed(prog: bytes, data: bytes) -> int:
    """Interpret assembled bytes against synthetic seccomp_data."""
    acc = 0
    pc = 0
    while True:
        code, jt, jf, k = struct.unpack_from("<HBBI", prog, pc * 8)
        if code == bpf.BPF_LD_ABS_W:
            acc = int.from_bytes(data[k : k + 4].ljust(4, b"\0"), "little")
            pc += 1
        elif code == bpf.BPF_ALU_AND_K:
            acc &= k
            pc += 1
        elif code == bpf.BPF_JA:
            pc += 1 + k
        elif code == bpf.BPF_JEQ:
            pc += 1 + (jt if acc == k else jf)
        elif code == bpf.BPF_JGT:
            pc += 1 + (jt if acc > k else jf)
        elif code == bpf.BPF_JGEQ:
            pc += 1 + (jt if acc >= k else jf)
        elif code == bpf.BPF_JSET:
            pc += 1 + (jt if acc & k else jf)
        elif code == bpf.BPF_RET_K:
            return int(k)
        else:  # pragma: no cover - generated programs only use known ops
            raise AssertionError(f"bad opcode {code:#x}")


def run_source(insns: list[bpf.Insn], labels: dict[str, int], data: bytes) -> int:
    """Interpret the symbolic program directly, for comparison."""
    acc = 0
    pc = 0
    while True:
        insn = insns[pc]
        if isinstance(insn, bpf.Load):
            acc = int.from_bytes(data[insn.k : insn.k + 4].ljust(4, b"\0"), "little")
            pc += 1
        elif isinstance(insn, bpf.And):
            acc &= insn.k
            pc += 1
        elif isinstance(insn, bpf.Jump):
            cond = {
                bpf.BPF_JEQ: acc == insn.k,
                bpf.BPF_JGT: acc > insn.k,
                bpf.BPF_JGEQ: acc >= insn.k,
                bpf.BPF_JSET: bool(acc & insn.k),
            }[insn.op]
            target = insn.jt if cond else insn.jf
            pc = labels[target] if target is not None else pc + 1
        elif isinstance(insn, bpf.Ja):
            pc = labels[insn.target]
        elif isinstance(insn, bpf.Ret):
            return insn.k
        else:  # pragma: no cover
            raise TypeError(f"bad insn {insn!r}")


def test_load_packs_exactly() -> None:
    prog = bpf.assemble([bpf.Load(4), bpf.Ret(ALLOW)], {})
    assert prog == pack(bpf.BPF_LD_ABS_W, 0, 0, 4) + pack(bpf.BPF_RET_K, 0, 0, ALLOW)


def test_conditional_jump_offsets() -> None:
    # ld arch, jeq arch -> +0 / kill, ld nr, jeq 39 -> allow / next, ret kill, ret allow
    insns: list[bpf.Insn] = [
        bpf.Load(4),
        bpf.Jump(bpf.BPF_JEQ, AUDIT_ARCH_X86_64, None, "kill"),
        bpf.Load(0),
        bpf.Jump(bpf.BPF_JEQ, 39, "allow", None),
        bpf.Ret(KILL_PROCESS),
        bpf.Ret(ALLOW),
    ]
    labels = {"kill": 4, "allow": 5}
    prog = bpf.assemble(insns, labels)
    assert prog == (
        pack(bpf.BPF_LD_ABS_W, 0, 0, 4)
        + pack(bpf.BPF_JEQ, 0, 2, AUDIT_ARCH_X86_64)
        + pack(bpf.BPF_LD_ABS_W, 0, 0, 0)
        + pack(bpf.BPF_JEQ, 1, 0, 39)
        + pack(bpf.BPF_RET_K, 0, 0, KILL_PROCESS)
        + pack(bpf.BPF_RET_K, 0, 0, ALLOW)
    )


def test_ja_encodes_forward_offset() -> None:
    insns: list[bpf.Insn] = [bpf.Ja("end"), bpf.Load(0), bpf.Ret(ALLOW)]
    prog = bpf.assemble(insns, {"end": 2})
    assert prog[:8] == pack(bpf.BPF_JA, 0, 0, 1)


def test_backward_jump_rejected() -> None:
    insns: list[bpf.Insn] = [bpf.Load(0), bpf.Ja("start"), bpf.Ret(ALLOW)]
    with pytest.raises(ValueError, match="backward"):
        bpf.assemble(insns, {"start": 0})


def test_undefined_label_rejected() -> None:
    insns: list[bpf.Insn] = [bpf.Jump(bpf.BPF_JEQ, 1, "nope", None), bpf.Ret(ALLOW)]
    with pytest.raises(ValueError, match="undefined label"):
        bpf.assemble(insns, {})


def test_bad_jump_opcode_rejected() -> None:
    with pytest.raises(ValueError, match="opcode"):
        bpf.Jump(bpf.BPF_JA, 0)


def test_far_jump_expands_to_trampoline() -> None:
    # 300 filler loads push the "far" target out of 8-bit range.
    insns: list[bpf.Insn] = [bpf.Load(0), bpf.Jump(bpf.BPF_JEQ, 42, "far", None)]
    insns += [bpf.Load(0)] * 300
    insns.append(bpf.Ret(KILL_PROCESS))
    insns.append(bpf.Ret(ALLOW))
    labels = {"far": len(insns) - 1}
    prog = bpf.assemble(insns, labels)

    # The jeq expanded to jeq jt=0 jf=1 plus a JA, so one extra insn.
    assert len(prog) == (len(insns) + 1) * 8
    assert prog[8:16] == pack(bpf.BPF_JEQ, 0, 1, 42)
    ja_code, _, _, ja_k = struct.unpack_from("<HBBI", prog, 16)
    assert ja_code == bpf.BPF_JA
    # JA at index 2 lands on the ALLOW ret at index 304.
    assert 2 + 1 + ja_k == 304

    data = (42).to_bytes(4, "little") + bytes(76)
    assert run_packed(prog, data) == ALLOW
    assert run_packed(prog, bytes(80)) == KILL_PROCESS


def test_far_jump_both_branches() -> None:
    insns: list[bpf.Insn] = [bpf.Load(0), bpf.Jump(bpf.BPF_JEQ, 7, "yes", "no")]
    insns += [bpf.Load(0)] * 300
    insns.append(bpf.Ret(ALLOW))
    insns.append(bpf.Ret(KILL_PROCESS))
    prog = bpf.assemble(insns, {"yes": 302, "no": 303})

    assert prog[8:16] == pack(bpf.BPF_JEQ, 0, 1, 7)
    code_t, _, _, k_t = struct.unpack_from("<HBBI", prog, 16)
    code_f, _, _, k_f = struct.unpack_from("<HBBI", prog, 24)
    assert (code_t, code_f) == (bpf.BPF_JA, bpf.BPF_JA)
    assert 2 + 1 + k_t == 304
    assert 3 + 1 + k_f == 305


@st.composite
def programs(draw: st.DrawFn) -> tuple[list[bpf.Insn], dict[str, int]]:
    """Random forward-only programs ending in Ret."""
    n = draw(st.integers(1, 30))
    label_positions = draw(
        st.lists(st.integers(0, n - 1), min_size=1, max_size=n, unique=True)
    )
    labels = {f"l{p}": p for p in sorted(label_positions)}
    forward = [name for name, pos in labels.items()]

    insns: list[bpf.Insn] = []
    for i in range(n - 1):
        later = [name for name in forward if labels[name] > i]
        kind = draw(st.sampled_from(["load", "jump", "ja", "ret", "and"]))
        if kind == "and":
            insns.append(bpf.And(draw(st.integers(0, 0xFFFFFFFF))))
        elif kind == "load" or not later:
            insns.append(bpf.Load(draw(st.integers(0, 60))))
        elif kind == "ja":
            insns.append(bpf.Ja(draw(st.sampled_from(later))))
        elif kind == "ret":
            insns.append(bpf.Ret(draw(st.integers(0, 0xFFFFFFFF))))
        else:
            jt = draw(st.sampled_from([*later, None]))
            jf = draw(st.sampled_from([*later, None]))
            op = draw(
                st.sampled_from([bpf.BPF_JEQ, bpf.BPF_JGT, bpf.BPF_JGEQ, bpf.BPF_JSET])
            )
            insns.append(bpf.Jump(op, draw(st.integers(0, 0xFFFFFFFF)), jt, jf))
    insns.append(bpf.Ret(draw(st.integers(0, 0xFFFFFFFF))))
    return insns, labels


@given(programs(), st.binary(min_size=0, max_size=80))
@settings(max_examples=500)
def test_assembled_program_matches_source(
    program: tuple[list[bpf.Insn], dict[str, int]], data: bytes
) -> None:
    insns, labels = program
    packed = bpf.assemble(insns, labels)
    assert len(packed) % 8 == 0
    assert run_packed(packed, data) == run_source(insns, labels, data)


@given(programs())
@settings(max_examples=300)
def test_all_conditional_offsets_fit(
    program: tuple[list[bpf.Insn], dict[str, int]],
) -> None:
    insns, labels = program
    packed = bpf.assemble(insns, labels)
    for i in range(len(packed) // 8):
        code, jt, jf, _ = struct.unpack_from("<HBBI", packed, i * 8)
        if code in (bpf.BPF_JEQ, bpf.BPF_JGT, bpf.BPF_JGEQ, bpf.BPF_JSET):
            assert jt <= 255
            assert jf <= 255
