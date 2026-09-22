# Changelog

## [Unreleased]

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
