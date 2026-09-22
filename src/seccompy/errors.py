# SPDX-License-Identifier: 0BSD
"""Exception types raised by seccompy."""


class SeccompError(OSError):
    """A seccomp-related syscall failed."""


class UnsupportedError(SeccompError):
    """The running kernel does not support seccomp or the requested feature."""
