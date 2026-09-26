# User notifications

Rules added with `Filter.notify()` delegate matching syscalls to a
supervisor through the `SECCOMP_RET_USER_NOTIF` protocol. Load the
filter with `FilterFlag.NEW_LISTENER` and `load()` returns a
`seccompy.notify.Listener` wrapping the notification file descriptor.
Requires Linux 5.0+.

```python
import ctypes
import errno
import os

from seccompy import Action, Filter, FilterFlag, notify

filt = Filter(default=Action.ALLOW, flags=FilterFlag.NEW_LISTENER)
filt.notify("mount")
listener = filt.load()

libc = ctypes.CDLL(None, use_errno=True)
pid = os.fork()
if pid == 0:  # target: inherits the filter and the listener fd
    libc.mount(None, None, None, 0, None)  # blocks until answered
    os._exit(0)

req = listener.recv()  # struct seccomp_notif: id, pid, args
listener.respond(req.id, error=errno.EPERM)  # spoof a failure
os.waitpid(pid, 0)
listener.close()
```

## The Listener API

The fd is pollable: it reads as readable when a notification is pending
and reports end-of-file once the last target thread has exited and been
reaped. Closing it (or letting the supervisor die) completes every
still-blocked notification with `ENOSYS`.

- `recv()` returns a `Notification` with `id`, `pid`, `flags`, `nr`,
  `arch`, `instruction_pointer` and `args`.
- `respond(id, error=..., val=...)` spoofs the return value, or
  `respond(id, flags=RespFlag.CONTINUE)` lets the kernel execute the
  syscall. `CONTINUE` requires `error` and `val` to be zero.
- `valid(id)` checks whether a notification still awaits a response. A
  positive answer can still go stale, so `respond()` may fail with
  `ENOENT` regardless.
- `addfd(id, local_fd, ...)` installs a supervisor fd into the target's
  fd table. `AddFdFlag.SETFD` selects the fd number via `newfd`,
  `AddFdFlag.SEND` completes the notification atomically, and
  `newfd_flags` accepts `os.O_CLOEXEC`.
- `set_flags(FdFlag.SYNC_WAKE_UP)` wakes the target on the CPU the
  response was sent from.

`Listener` validates the kernel's notification ABI sizes from
`SECCOMP_GET_NOTIF_SIZES` at construction and owns the fd: use it as a
context manager or call `close()`.

## Supervising another process

`notify.pidfd_open(pid)` and `notify.pidfd_getfd(pidfd, fd)` wrap the
pidfd syscalls so a supervisor can grab the notification fd out of a
filtered child. `pidfd_getfd` requires ptrace-level access on the
target.

## Caveats

The supervisor must never invoke a notified syscall itself: it would
queue a notification nobody can answer and block forever. Per the kernel
documentation the mechanism exists for performing syscalls on behalf of
a lesser-privileged target, not for implementing security policy.
`RespFlag.CONTINUE` in particular is subject to a TOCTOU race, since the
target can rewrite pointer arguments while it waits for the response.

- https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html
