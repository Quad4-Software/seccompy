# SPDX-License-Identifier: 0BSD
"""Helpers for testing code against seccomp filters.

probe() runs a callable in a forked child process under a filter, so
tests and applications can verify what a policy does before enforcing
it for real.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass

from .filter import Filter

__all__ = ["ProbeResult", "probe"]


@dataclass(frozen=True)
class ProbeResult:
    """Outcome of a probe() run.

    ok is True when fn completed under the filter. When fn or the load
    raised an OSError, errno holds its errno value. signal is nonzero
    if the child was killed instead, for example by a KILL action which
    delivers SIGSYS.
    """

    ok: bool
    errno: int = 0
    signal: int = 0


def probe(filt: Filter, fn: Callable[[], object]) -> ProbeResult:
    """Run fn in a forked child process restricted by filt.

    The filter must not be loaded. It is loaded in the child only, so
    the caller's copy stays usable. The return value of fn is discarded.
    The child exits with os._exit, so atexit handlers, buffered I/O and
    threads do not run there.
    """
    if filt.loaded:
        raise RuntimeError("filter is already loaded")

    pid = os.fork()
    if pid == 0:
        try:
            filt.load()
            fn()
        except OSError as exc:
            os._exit(exc.errno if exc.errno is not None else 1)
        except BaseException:  # noqa: BLE001 - the child must not propagate
            os._exit(255)
        os._exit(0)

    _, status = os.waitpid(pid, 0)
    if os.WIFSIGNALED(status):
        return ProbeResult(ok=False, signal=os.WTERMSIG(status))
    code = os.WEXITSTATUS(status)
    if code == 0:
        return ProbeResult(ok=True)
    return ProbeResult(ok=False, errno=code)
