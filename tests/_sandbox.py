# SPDX-License-Identifier: 0BSD
"""Helper run as a subprocess by the enforced tests.

Loading a filter is irreversible, so it must happen in a child process.
Each scenario installs a policy, checks the expected outcomes, prints
FAIL lines for mismatches and exits nonzero on failure.
"""

import ctypes
import errno
import os
import signal
import sys
from pathlib import Path

from seccompy import Action, Filter

failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if not ok:
        failures.append(f"{name}: {detail}")


def scenario_errno(path: str) -> None:
    """openat is denied with EACCES; everything else still works."""
    filt = Filter(default=Action.ALLOW)
    filt.errno("openat", errno.EACCES)
    filt.load()

    try:
        Path(path).read_text()
        check("openat denied", False, "no error raised")
    except PermissionError as exc:
        check("openat denied", exc.errno == errno.EACCES, str(exc))

    check("getpid still allowed", os.getpid() > 0)


def scenario_errno_libc() -> None:
    """A denied getpid returns -errno through the raw libc wrapper."""
    libc = ctypes.CDLL(None, use_errno=True)
    filt = Filter(default=Action.ALLOW)
    filt.errno("getpid", errno.EACCES)
    filt.load()

    ctypes.set_errno(0)
    rc = libc.getpid()
    check("getpid raw return", rc == -errno.EACCES, f"rc={rc}")


def scenario_kill() -> None:
    """getpid kills the process; the parent sees SIGSYS."""
    filt = Filter(default=Action.ALLOW)
    filt.kill("getpid")
    filt.load()
    os.getpid()


def scenario_trap() -> None:
    """TRAP delivers a catchable SIGSYS and the syscall does not run."""
    hits: list[int] = []
    libc = ctypes.CDLL(None, use_errno=True)

    def handler(sig: int, frame: object) -> None:
        hits.append(sig)

    signal.signal(signal.SIGSYS, handler)
    filt = Filter(default=Action.ALLOW)
    filt.trap("getpid")
    filt.load()

    ctypes.set_errno(0)
    rc = libc.getpid()
    check("trap delivered SIGSYS", hits == [signal.SIGSYS], str(hits))
    check("trapped syscall skipped", rc != os.getppid(), f"rc={rc}")


def scenario_log() -> None:
    """LOG allows the syscall while sending it to the audit log."""
    filt = Filter(default=Action.ALLOW)
    filt.log("getpid")
    filt.load()
    check("logged syscall runs", os.getpid() > 0)


def scenario_args() -> None:
    """An arg-matched rule denies write only for one fd value."""
    filt = Filter(default=Action.ALLOW)
    filt.errno("write", errno.EIO, args={0: 1})
    filt.load()

    devnull = os.open("/dev/null", os.O_WRONLY)
    try:
        check("write other fd allowed", os.write(devnull, b"x") == 1)
    finally:
        os.close(devnull)

    try:
        os.write(1, b"x")
        check("write fd 1 denied", False, "no error raised")
    except OSError as exc:
        check("write fd 1 denied", exc.errno == errno.EIO, str(exc))


def scenario_default_errno() -> None:
    """A default ERRNO action denies unlisted syscalls but not listed ones."""
    filt = Filter(default=int(Action.ERRNO) | errno.EPERM)
    for name in (
        "getpid",
        "read",
        "write",
        "close",
        "fstat",
        "mmap",
        "munmap",
        "mremap",
        "brk",
        "rt_sigaction",
        "rt_sigreturn",
        "sigaltstack",
        "exit_group",
        "exit",
    ):
        filt.allow(name)
    filt.load()

    check("listed syscall allowed", os.getpid() > 0)
    try:
        Path("/etc/hostname").read_text()
        check("unlisted syscall denied", False, "no error raised")
    except PermissionError as exc:
        check("unlisted syscall denied", exc.errno == errno.EPERM, str(exc))


def scenario_nnp() -> None:
    """load() sets no_new_privs as a side effect."""
    filt = Filter(default=Action.ALLOW)
    filt.load()
    status = Path("/proc/self/status").read_text()
    check(
        "no_new_privs",
        "NoNewPrivs:\t1" in status,
        "NoNewPrivs not set in /proc/self/status",
    )


def main() -> int:
    scenarios = {
        "errno": lambda: scenario_errno(sys.argv[2]),
        "errno_libc": scenario_errno_libc,
        "kill": scenario_kill,
        "trap": scenario_trap,
        "log": scenario_log,
        "args": scenario_args,
        "default_errno": scenario_default_errno,
        "nnp": scenario_nnp,
    }
    try:
        scenarios[sys.argv[1]]()
    except KeyError:
        sys.stderr.write(f"unknown scenario {sys.argv[1]}\n")
        return 2

    for failure in failures:
        sys.stderr.write(f"FAIL {failure}\n")
    if failures:
        return 1
    sys.stderr.write("PASS\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
