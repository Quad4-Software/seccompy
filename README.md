# seccompy

[![CI](https://github.com/Quad4-Software/seccompy/actions/workflows/ci.yml/badge.svg)](https://github.com/Quad4-Software/seccompy/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Quad4-Software/seccompy/actions/workflows/codeql.yml/badge.svg)](https://github.com/Quad4-Software/seccompy/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Quad4-Software/seccompy/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Quad4-Software/seccompy)
[![PyPI](https://img.shields.io/pypi/v/seccompy.svg)](https://pypi.org/project/seccompy/)
[![License: 0BSD](https://img.shields.io/badge/license-0BSD-blue)](LICENSE)

Dependency-free Python bindings for Linux seccomp-BPF syscall filtering.
Filters are assembled in pure Python from symbolic instructions, checked
against the native architecture to block ABI confusion, and installed
through seccomp(2) with prctl(PR_SET_NO_NEW_PRIVS), so no compiler,
libbpf or privileges are needed.

Requires Python 3.10+ and Linux 3.17+ on x86_64 or aarch64.

## Install

    pip install seccompy

## Usage

```python
import errno

from seccompy import Action, Filter

filt = Filter(default=Action.ALLOW)
filt.errno("openat", errno.EACCES)
filt.kill("ptrace")
filt.log("mount")
filt.load()

# openat now fails with EACCES for this thread and its children,
# ptrace kills the process, mount is allowed but logged
```

Rules can also match on 64-bit syscall arguments:

```python
filt.errno("write", errno.EIO, args={0: 1})  # deny write() on fd 1 only
```

Beyond equality, ArgCmp conditions support unsigned comparisons and
masked equality over the whole 64-bit argument:

```python
import os

from seccompy import ArgCmp, CmpOp

filt.errno("write", errno.EIO, args=[ArgCmp(0, CmpOp.GT, 4096)])
# deny openat(O_RDONLY): masked equality is needed since O_RDONLY is 0
filt.errno(
    "openat", errno.EACCES, args=[ArgCmp(2, CmpOp.MASKED_EQ, 0, mask=os.O_ACCMODE)]
)
```

With FilterFlag.NEW_LISTENER, load() returns a notification fd wrapped
in seccompy.notify.Listener, and Filter.notify() rules delegate matching
syscalls to a supervisor process (kernel 5.0+):

```python
import ctypes
import errno
import os

from seccompy import Action, Filter, FilterFlag, notify

filt = Filter(default=Action.ALLOW, flags=FilterFlag.NEW_LISTENER)
filt.notify("mount")
listener = filt.load()
assert listener is not None

libc = ctypes.CDLL(None, use_errno=True)
pid = os.fork()
if pid == 0:  # target: inherits the filter and the listener fd
    libc.mount(None, None, None, 0, None)  # blocks until answered
    os._exit(0)

req = listener.recv()  # struct seccomp_notif: id, pid, args
listener.respond(req.id, error=errno.EPERM)  # spoof a failure
# or: listener.respond(req.id, flags=notify.RespFlag.CONTINUE)
os.waitpid(pid, 0)
listener.close()
```

The listener fd is pollable and also supports valid(), addfd() for fd
injection and set_flags(). notify.pidfd_open/pidfd_getfd cover the
supervisor-in-another-process case. The supervisor process must never
call a notified syscall itself, or it blocks on its own listener.
See seccomp_unotify(2) for the protocol and its caveats.

`seccompy.supported()` reports whether the running kernel can install
filters, `seccompy.action_supported(Action.X)` probes a return action
and `seccompy.flag_supported(FilterFlag.X)` probes a load flag. The
compiled BPF program is available as `filt.program` for inspection, and
`seccompy.testing.probe()` runs a callable under a filter in a forked
child to preview enforcement.

## Documentation

- API: docstrings in `src/seccompy/`, mostly `filter.py`
- seccomp reference: https://docs.kernel.org/userspace-api/seccomp_filter.html
- seccomp(2) man page: https://man7.org/linux/man-pages/man2/seccomp.2.html

License: 0BSD.
