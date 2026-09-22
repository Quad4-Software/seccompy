# SPDX-License-Identifier: 0BSD
"""Tests for the syscall name and number tables."""

import pytest

from seccompy import (
    AUDIT_ARCH_AARCH64,
    AUDIT_ARCH_X86_64,
    arch,
    audit_arch,
    syscall_name,
    syscall_nr,
)
from seccompy.syscalls import AARCH64_SYSCALLS, X86_64_SYSCALLS


def test_x86_64_table() -> None:
    assert X86_64_SYSCALLS["read"] == 0
    assert X86_64_SYSCALLS["getpid"] == 39
    assert X86_64_SYSCALLS["openat"] == 257
    assert X86_64_SYSCALLS["seccomp"] == 317
    assert X86_64_SYSCALLS["clone3"] == 435


def test_aarch64_table() -> None:
    assert AARCH64_SYSCALLS["read"] == 63
    assert AARCH64_SYSCALLS["getpid"] == 172
    assert AARCH64_SYSCALLS["openat"] == 56
    assert AARCH64_SYSCALLS["seccomp"] == 277


def test_audit_arch_constants() -> None:
    assert AUDIT_ARCH_X86_64 == 0xC000003E
    assert AUDIT_ARCH_AARCH64 == 0xC00000B7
    assert audit_arch() in (AUDIT_ARCH_X86_64, AUDIT_ARCH_AARCH64)
    assert arch() in ("x86_64", "aarch64")


def test_syscall_nr_resolves_native() -> None:
    native = {"x86_64": 39, "aarch64": 172}[arch()]
    assert syscall_nr("getpid") == native
    assert syscall_nr(native) == native


def test_syscall_name_roundtrip() -> None:
    assert syscall_name(syscall_nr("openat")) == "openat"


def test_syscall_nr_unknown_name() -> None:
    with pytest.raises(ValueError, match="unknown syscall"):
        syscall_nr("definitely_not_a_syscall")


def test_syscall_name_unknown_nr() -> None:
    with pytest.raises(ValueError, match="unknown syscall number"):
        syscall_name(0xDEADBEEF)


def test_syscall_nr_rejects_out_of_range() -> None:
    with pytest.raises(ValueError, match="out of range"):
        syscall_nr(-1)
    with pytest.raises(ValueError, match="out of range"):
        syscall_nr(1 << 32)
