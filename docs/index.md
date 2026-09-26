# seccompy

Dependency-free Python bindings for Linux seccomp-BPF syscall filtering.

Filters are assembled in pure Python from symbolic instructions, checked
against the native architecture to block ABI confusion, and installed
through `seccomp(2)` with `prctl(PR_SET_NO_NEW_PRIVS)`, so no compiler,
libbpf or privileges are needed.

Requires Python 3.10+ and Linux 3.17+ on x86_64 or aarch64.

## Install

```
pip install seccompy
```

## Quick start

```python
import errno

from seccompy import Action, Filter

filt = Filter(default=Action.ALLOW)
filt.errno("openat", errno.EACCES)
filt.kill("ptrace")
filt.log("mount")
filt.load()
```

Once loaded, `openat` fails with `EACCES` for the calling thread and its
children, `ptrace` kills the process, and `mount` is allowed but logged.
Loading a filter is irreversible.

Rules can also match on 64-bit syscall arguments:

```python
filt.errno("write", errno.EIO, args={0: 1})  # deny write() on fd 1 only
```

and full unsigned comparisons with `ArgCmp`:

```python
import os

from seccompy import ArgCmp, CmpOp

filt.errno("write", errno.EIO, args=[ArgCmp(0, CmpOp.GT, 4096)])
filt.errno(
    "openat", errno.EACCES, args=[ArgCmp(2, CmpOp.MASKED_EQ, 0, mask=os.O_ACCMODE)]
)
```

## Feature probes

```python
import seccompy

seccompy.supported()  # kernel can install filters
seccompy.action_supported(seccompy.Action.LOG)
seccompy.flag_supported(seccompy.FilterFlag.NEW_LISTENER)
```

## Next steps

- [Filters](filters.md): rules, actions, argument conditions, probes
- [User notifications](notifications.md): delegating syscalls to a supervisor
- [API reference](api.md): the full public surface
