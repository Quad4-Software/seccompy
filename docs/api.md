# API reference

## Top level: `seccompy`

| Name | Description |
| --- | --- |
| `Filter` | Filter under construction; see [Filters](filters.md) |
| `Action` | `SECCOMP_RET_*` return actions |
| `FilterFlag` | `SECCOMP_FILTER_FLAG_*` load flags |
| `ArgCmp` | One condition on a 64-bit syscall argument |
| `CmpOp` | Comparison operators mirroring `SCMP_CMP_*` |
| `ArgCond`, `Args` | Accepted argument-condition shapes |
| `SeccompError` | `OSError` carrying the real kernel errno |
| `UnsupportedError` | Kernel lacks seccomp or the requested feature |
| `supported()` | Whether the kernel can install filters |
| `action_supported(action)` | Probe a `SECCOMP_RET_*` action |
| `flag_supported(flag)` | Probe a `SECCOMP_FILTER_FLAG_*` flag |
| `syscall_nr(name)` | Resolve a syscall name to its native number |
| `syscall_name(nr)` | Resolve a number to its native name |
| `arch()` | `x86_64` or `aarch64` |
| `audit_arch()` | Native `AUDIT_ARCH_*` constant |
| `AUDIT_ARCH_X86_64`, `AUDIT_ARCH_AARCH64` | Arch constants |
| `__version__` | Package version |

## `seccompy.notify`

Supervisor side of the `SECCOMP_RET_USER_NOTIF` protocol. See
[User notifications](notifications.md).

| Name | Description |
| --- | --- |
| `Listener` | Pollable notification fd with `recv`, `respond`, `valid`, `addfd`, `set_flags`, `close` |
| `Notification` | One pending event: `id`, `pid`, `flags`, `nr`, `arch`, `instruction_pointer`, `args` |
| `NotifSizes` | Kernel ABI sizes from `SECCOMP_GET_NOTIF_SIZES` |
| `RespFlag` | `CONTINUE` response flag |
| `AddFdFlag` | `SETFD` and `SEND` flags for `addfd` |
| `FdFlag` | `SYNC_WAKE_UP` for `set_flags` |
| `sizes()` | Query the kernel's notification struct sizes |
| `pidfd_open(pid)` | Open a pidfd for a process |
| `pidfd_getfd(pidfd, fd)` | Duplicate an fd out of a pidfd target |

## `seccompy.bpf`

Classic BPF instruction model and assembler. `assemble()` resolves
symbolic labels into the 8-bit relative offsets `struct sock_filter`
requires, expanding conditional jumps beyond 255 instructions into
hop-plus-`JA` trampolines.

| Name | Description |
| --- | --- |
| `Load(k)` | Load the 32-bit word at byte offset `k` |
| `And(k)` | `A &= k` |
| `Jump(op, k, jt, jf)` | Conditional jump; `None` falls through |
| `Ja(target)` | Unconditional jump to a label |
| `Ret(k)` | Terminate with result `k` |
| `assemble(insns, labels)` | Pack to `sock_filter` bytes |
| `BPF_LD_ABS_W` and friends | Opcode constants |

## `seccompy.testing`

| Name | Description |
| --- | --- |
| `probe(filt, fn)` | Run `fn` under `filt` in a forked child |
| `ProbeResult` | `ok`, `errno`, `signal` fields |

## `seccompy.syscalls`

`X86_64_SYSCALLS` and `AARCH64_SYSCALLS` name tables generated from the
kernel UAPI headers, plus `arch()`, `audit_arch()`, `syscall_nr()` and
`syscall_name()`.
