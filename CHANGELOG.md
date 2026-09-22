# Changelog

## [0.2.0] - Unreleased

- Argument conditions beyond equality: CmpOp operators EQ, NE, LT, LE,
  GT, GE and MASKED_EQ on the full 64-bit syscall arguments, via the
  frozen ArgCmp dataclass or (index, op, value[, mask]) tuples. The
  classic index->value mapping still works and means equality. Masked
  equality uses the kernel-allowed BPF ALU AND instruction.
- SECCOMP_RET_USER_NOTIF support: Action.USER_NOTIF and Filter.notify()
  add rules that delegate matching syscalls to a supervisor. With
  FilterFlag.NEW_LISTENER, Filter.load() returns the notification fd
  wrapped in seccompy.notify.Listener.
- New seccompy.notify module implementing the supervisor side of the
  user notification protocol: Listener.recv() for Notification events,
  respond() with spoofed errno/values or RespFlag.CONTINUE, valid() for
  SECCOMP_IOCTL_NOTIF_ID_VALID, addfd() for fd injection (SETFD and the
  atomic SEND), set_flags() for SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP, and
  sizes() reporting the kernel's struct sizes, which Listener validates
  on construction. pidfd_open()/pidfd_getfd() wrappers cover the
  supervisor-in-another-process case.

## [0.1.0] - 2026-09-22

Initial release.

- Pure-Python classic BPF assembler for struct sock_filter programs,
  with symbolic labels, forward-jump resolution and automatic JA
  trampolines for conditional jumps beyond the 8-bit offset limit.
- Filter API with a default action plus per-syscall rules: allow(),
  kill() (KILL_PROCESS), kill_thread(), trap(), errno(), trace() and
  log(), each optionally gated on equality of 64-bit syscall arguments.
- Compiled programs always verify seccomp_data.arch against the native
  AUDIT_ARCH_* value and kill foreign-ABI syscalls.
- Raw ctypes bindings for seccomp(2) and prctl(PR_SET_NO_NEW_PRIVS),
  with real kernel errnos preserved on SeccompError/UnsupportedError.
- Kernel feature probes: supported(), action_supported() via
  SECCOMP_GET_ACTION_AVAIL and flag_supported() via NULL-program flag
  validation.
- Full x86_64 and aarch64 syscall name/number tables generated from the
  kernel UAPI headers, with syscall_nr() and syscall_name() helpers.
- testing.probe() to run a callable under a filter in a forked child.
