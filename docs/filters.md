# Filters

A `Filter` declares a default action plus per-syscall rules, then
compiles to a classic BPF program the kernel runs against
`struct seccomp_data` on every syscall entry.

```python
filt = Filter(default=Action.ALLOW)  # or a raw SECCOMP_RET_* int
filt.errno("openat", errno.EACCES)
filt.kill("ptrace")
filt.load()
```

`load()` sets `no_new_privs` on the calling thread and installs the
filter via `seccomp(2)`. Loading is irreversible, the filter refuses
mutation once loaded, and children inherit it.

## Actions

Every rule method takes a syscall name or number, plus an optional
`args` gate:

| Method | Kernel action |
| --- | --- |
| `allow(name)` | `SECCOMP_RET_ALLOW` |
| `kill(name)` | `SECCOMP_RET_KILL_PROCESS` |
| `kill_thread(name)` | `SECCOMP_RET_KILL_THREAD` |
| `trap(name)` | `SECCOMP_RET_TRAP` (delivers SIGSYS) |
| `errno(name, e)` | `SECCOMP_RET_ERRNO` with `e` as the 16-bit data |
| `trace(name, msg)` | `SECCOMP_RET_TRACE` with `msg` as the 16-bit data |
| `log(name)` | `SECCOMP_RET_LOG` |
| `notify(name)` | `SECCOMP_RET_USER_NOTIF`, see [notifications](notifications.md) |

Rules for the same syscall are evaluated in insertion order and the
first match wins.

## Argument conditions

`args` accepts an `index -> value` mapping for equality, or an iterable
of `ArgCmp` objects or `(index, op, value[, mask])` tuples:

```python
from seccompy import ArgCmp, CmpOp

filt.errno("write", errno.EIO, args=[ArgCmp(0, CmpOp.GT, 4096)])
```

`CmpOp` mirrors `SCMP_CMP_*`: `EQ`, `NE`, `LT`, `LE`, `GT`, `GE` and
`MASKED_EQ`. All comparisons are unsigned and apply to the full 64-bit
argument. `MASKED_EQ` tests `arg & mask == value`, which is the only way
to match flag bits whose value is zero, such as `O_RDONLY`:

```python
filt.errno(
    "openat", errno.EACCES, args=[ArgCmp(2, CmpOp.MASKED_EQ, 0, mask=os.O_ACCMODE)]
)
```

## Flags

`Filter(flags=...)` accepts `FilterFlag` values mirroring
`SECCOMP_FILTER_FLAG_*`: `TSYNC`, `LOG`, `SPEC_ALLOW`, `NEW_LISTENER`,
`TSYNC_ESRCH` and `WAIT_KILLABLE_RECV`. Probe them before relying on
them:

```python
seccompy.flag_supported(FilterFlag.TSYNC)
```

## Inspecting and probing

`filt.program` returns the compiled BPF program as packed
`sock_filter` bytes for inspection. `seccompy.testing.probe()` runs a
callable under the filter in a forked child, so a policy can be verified
before it is enforced for real:

```python
import seccompy

filt = seccompy.Filter(default=seccompy.Action.ALLOW)
filt.kill("getpid")
result = seccompy.testing.probe(filt, os.getpid)
assert result.signal == signal.SIGSYS
```

## Architecture checking

Every compiled program first compares `seccomp_data.arch` against the
native `AUDIT_ARCH_*` value and kills foreign-ABI syscalls. This blocks
the syscall-number confusion described in the kernel documentation, for
example a 32-bit `int 0x80` entry on x86_64.

## Kernel reference

- https://docs.kernel.org/userspace-api/seccomp_filter.html
- https://man7.org/linux/man-pages/man2/seccomp.2.html
