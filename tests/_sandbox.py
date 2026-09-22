# SPDX-License-Identifier: 0BSD
"""Helper run as a subprocess by the enforced tests.

Loading a filter is irreversible, so it must happen in a child process.
Each scenario installs a policy, checks the expected outcomes, prints
FAIL lines for mismatches and exits nonzero on failure.
"""

import ctypes
import errno
import os
import select
import signal
import sys
from pathlib import Path

from seccompy import Action, Filter, FilterFlag, notify, syscall_nr
from seccompy.syscalls import audit_arch

failures: list[str] = []


class _SkipError(Exception):
    """Raised to mark a scenario as skipped (exit code 77)."""


def skip(reason: str) -> None:
    raise _SkipError(reason)


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


class _Utsname(ctypes.Structure):
    _fields_ = [
        ("sysname", ctypes.c_char * 65),
        ("nodename", ctypes.c_char * 65),
        ("release", ctypes.c_char * 65),
        ("version", ctypes.c_char * 65),
        ("machine", ctypes.c_char * 65),
        ("domainname", ctypes.c_char * 65),
    ]


def _listen(notified: str) -> notify.Listener:
    """Install a NEW_LISTENER filter notifying on one syscall.

    The filter is loaded in this process before fork: the child
    inherits both the filter and the notification fd, which the
    parent half of the scenario supervises. The notified syscall must
    be one the supervisor side never calls, or it would block on its
    own listener. In particular openat cannot be used: CPython calls
    it while os.fork() finishes in the parent, which deadlocks the
    supervisor on its own notification.
    """
    filt = Filter(default=Action.ALLOW, flags=FilterFlag.NEW_LISTENER)
    filt.notify(notified)
    listener = filt.load()
    assert listener is not None
    return listener


def _recv(listener: notify.Listener) -> notify.Notification:
    poller = select.poll()
    poller.register(listener, select.POLLIN)
    if not poller.poll(15000):
        raise RuntimeError("timed out waiting for a notification")
    return listener.recv()


def scenario_notify_errno() -> None:
    """A notified mount gets a spoofed EPERM from the supervisor."""
    libc = ctypes.CDLL(None, use_errno=True)
    with _listen("mount") as listener:
        pid = os.fork()
        if pid == 0:
            ctypes.set_errno(0)
            rc = libc.mount(None, None, None, 0, None)
            err = ctypes.get_errno()
            os._exit(0 if rc == -1 and err == errno.EPERM else 3)

        notif = _recv(listener)
        check("notif nr", notif.nr == syscall_nr("mount"), str(notif.nr))
        check("notif pid", notif.pid == pid, f"{notif.pid} != {pid}")
        check("notif flags", notif.flags == 0, str(notif.flags))
        check("notif arch", notif.arch == audit_arch(), hex(notif.arch))
        check("id valid", listener.valid(notif.id))
        listener.respond(notif.id, error=errno.EPERM)
        check("id invalid after reply", not listener.valid(notif.id))
        _, status = os.waitpid(pid, 0)
        check(
            "child observed EPERM",
            os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0,
            str(status),
        )


def scenario_notify_continue() -> None:
    """CONTINUE lets the target's uname run for real."""
    libc = ctypes.CDLL(None, use_errno=True)
    cr, cw = os.pipe()
    with _listen("uname") as listener:
        pid = os.fork()
        if pid == 0:
            os.close(cr)
            buf = _Utsname()
            ctypes.set_errno(0)
            if libc.uname(ctypes.byref(buf)) != 0:
                os._exit(4)
            os.write(cw, buf.sysname)
            os._exit(0)

        os.close(cw)
        notif = _recv(listener)
        check("notif nr", notif.nr == syscall_nr("uname"), str(notif.nr))
        check("notif pid", notif.pid == pid, f"{notif.pid} != {pid}")
        check("notif buf arg", notif.args[0] != 0, hex(notif.args[0]))
        listener.respond(notif.id, flags=notify.RespFlag.CONTINUE)
        reported = os.read(cr, 64)
        os.close(cr)
        check("continued syscall ran", reported == b"Linux", repr(reported))
        _, status = os.waitpid(pid, 0)
        check(
            "child exit",
            os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0,
            str(status),
        )


def scenario_notify_dead() -> None:
    """Responding after the target died fails with ENOENT."""
    libc = ctypes.CDLL(None, use_errno=True)
    with _listen("mount") as listener:
        pid = os.fork()
        if pid == 0:
            libc.mount(None, None, None, 0, None)  # blocks until killed
            os._exit(0)

        notif = _recv(listener)
        check("id valid", listener.valid(notif.id))
        os.kill(pid, signal.SIGKILL)
        _, status = os.waitpid(pid, 0)
        check(
            "child killed",
            os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL,
            str(status),
        )
        try:
            listener.respond(notif.id, error=errno.EIO)
            check("respond to dead", False, "no error raised")
        except OSError as exc:
            check("respond to dead", exc.errno == errno.ENOENT, str(exc))
        check("valid on dead", not listener.valid(notif.id))


def scenario_notify_close() -> None:
    """Closing the listener completes blocked syscalls with ENOSYS."""
    libc = ctypes.CDLL(None, use_errno=True)
    listener = _listen("mount")
    pid = os.fork()
    if pid == 0:
        # ENOSYS only fires once the last reference to the notification
        # fd is gone; the child inherited one across fork.
        listener.close()
        ctypes.set_errno(0)
        rc = libc.mount(None, None, None, 0, None)
        err = ctypes.get_errno()
        os._exit(0 if rc == -1 and err == errno.ENOSYS else 5)

    notif = _recv(listener)
    check("id valid", listener.valid(notif.id))
    listener.close()
    check("closed", listener.closed)
    _, status = os.waitpid(pid, 0)
    check(
        "child saw ENOSYS",
        os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0,
        str(status),
    )


def scenario_notify_addfd() -> None:
    """ADDFD SEND injects a supervisor fd into the target atomically."""
    libc = ctypes.CDLL(None, use_errno=True)
    devnull = os.open("/dev/null", os.O_RDONLY)
    cr, cw = os.pipe()
    try:
        with _listen("dup") as listener:
            pid = os.fork()
            if pid == 0:
                os.close(cr)
                ctypes.set_errno(0)
                fd = libc.dup(-1)  # invalid fd, replaced by the injected one
                if fd < 0:
                    os._exit(6)
                data = os.read(fd, 16)  # /dev/null reads as EOF
                os.write(cw, str(fd).encode() + b":" + data)
                os._exit(0)

            os.close(cw)
            notif = _recv(listener)
            check("notif nr", notif.nr == syscall_nr("dup"), str(notif.nr))
            check(
                "notif fd arg",
                notif.args[0] == 0xFFFFFFFFFFFFFFFF,
                hex(notif.args[0]),
            )
            try:
                remote = listener.addfd(
                    notif.id,
                    devnull,
                    flags=notify.AddFdFlag.SEND,
                    newfd_flags=os.O_CLOEXEC,
                )
            except OSError as exc:
                if exc.errno == errno.EINVAL:
                    os.waitpid(pid, 0)
                    skip("kernel lacks SECCOMP_ADDFD_FLAG_SEND")
                raise
            check("addfd remote fd", remote >= 0, str(remote))
            reported = os.read(cr, 64)
            os.close(cr)
            check(
                "child got injected fd",
                reported == f"{remote}:".encode(),
                repr(reported),
            )
            _, status = os.waitpid(pid, 0)
            check(
                "child exit",
                os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0,
                str(status),
            )
    finally:
        os.close(devnull)


def scenario_pidfd() -> None:
    """pidfd_open + pidfd_getfd duplicate an fd out of a child."""
    r, w = os.pipe()
    gate_r, gate_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        os.close(gate_w)
        fd = os.open("/dev/null", os.O_RDONLY)
        os.write(w, str(fd).encode())
        os.close(w)
        os.read(gate_r, 1)  # wait until the parent grabbed the fd
        os.close(fd)
        os._exit(0)

    os.close(w)
    os.close(gate_r)
    fd_no = int(os.read(r, 64))
    os.close(r)
    try:
        pidfd = notify.pidfd_open(pid)
        dup = notify.pidfd_getfd(pidfd, fd_no)
        os.close(pidfd)
    except OSError as exc:
        os.write(gate_w, b"x")
        os.close(gate_w)
        os.waitpid(pid, 0)
        if exc.errno in (errno.EPERM, errno.EACCES, errno.ENOSYS):
            skip(f"pidfd_getfd unavailable: {exc}")
        raise
    check("dup reads devnull", os.read(dup, 1) == b"")
    check(
        "dup is devnull",
        os.fstat(dup).st_rdev == Path("/dev/null").stat().st_rdev,
    )
    os.close(dup)
    os.write(gate_w, b"x")
    os.close(gate_w)
    _, status = os.waitpid(pid, 0)
    check(
        "child exit", os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, str(status)
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
        "notify_errno": scenario_notify_errno,
        "notify_continue": scenario_notify_continue,
        "notify_dead": scenario_notify_dead,
        "notify_close": scenario_notify_close,
        "notify_addfd": scenario_notify_addfd,
        "pidfd": scenario_pidfd,
    }
    try:
        scenarios[sys.argv[1]]()
    except KeyError:
        sys.stderr.write(f"unknown scenario {sys.argv[1]}\n")
        return 2
    except _SkipError as exc:
        sys.stderr.write(f"SKIP {exc}\n")
        return 77

    for failure in failures:
        sys.stderr.write(f"FAIL {failure}\n")
    if failures:
        return 1
    sys.stderr.write("PASS\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
