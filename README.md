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
