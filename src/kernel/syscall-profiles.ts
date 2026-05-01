// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Capt. Anil Sharma (rocketlang). All rights reserved.
// @rule:KOS-016 Claude Code baseline syscall set — minimum permitted for all agents

// KOS-016 baseline — every agent regardless of trust_mask
//
// NO-FREEZE GUARANTEE — these syscalls MUST always be present:
//   exit_group, exit   — process must always be able to terminate
//   futex              — blocking primitive; absent = threading deadlock
//   rt_sigreturn       — signal handlers cannot return without this
//   restart_syscall    — kernel restarts interrupted syscalls; absent = EINTR storm
//   clone3             — Bun ≥1.0 and Node ≥18 use this for thread creation
//
// defaultAction is SCMP_ACT_ERRNO (EPERM), never SCMP_ACT_KILL.
// A blocked syscall returns an error; it does not freeze or panic the kernel.
export const BASELINE_SYSCALLS: string[] = [
  "read", "write", "open", "openat", "close",
  "stat", "fstat", "lstat", "newfstatat",
  "mmap", "munmap", "mprotect", "brk",
  // --- NO-FREEZE CRITICAL — never remove these ---
  "exit_group", "exit",
  "futex",
  "rt_sigreturn",
  "restart_syscall",
  // -----------------------------------------------
  "nanosleep",
  "getpid", "gettid", "getcwd", "getdents64",
  "socket", "connect", "sendto", "recvfrom",
  "execve", "wait4", "clone", "clone3", "fork",
  // Required by Bun runtime
  "ioctl", "fcntl", "dup", "dup2", "dup3",
  "pipe", "pipe2", "select", "pselect6",
  "poll", "ppoll", "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait",
  "gettimeofday", "clock_gettime", "clock_nanosleep",
  "sigaltstack", "rt_sigaction", "rt_sigprocmask",
  "getrusage", "sysinfo", "times",
  "madvise", "mincore", "msync",
  "getuid", "getgid", "geteuid", "getegid",
  "setuid", "setgid",
  "readlink", "readlinkat",
  "access", "faccessat", "faccessat2",
  "uname", "sethostname",
  "pread64", "pwrite64", "readv", "writev", "preadv", "pwritev",
  "lseek", "ftruncate", "truncate",
  "mkdir", "mkdirat", "rmdir",
  "rename", "renameat", "renameat2",
  "unlink", "unlinkat",
  "chmod", "fchmod", "fchmodat",
  "chown", "fchown", "lchown", "fchownat",
  "sendmsg", "recvmsg", "sendmmsg", "recvmmsg",
  "getsockname", "getpeername", "getsockopt", "setsockopt",
  "bind", "listen", "accept", "accept4",
  "shutdown",
  "statfs", "fstatfs",
  "utime", "utimes", "utimensat", "futimesat",
  "getrandom",
  "sched_yield", "sched_getaffinity", "sched_setaffinity",
  "prctl",
  "arch_prctl",
  "set_tid_address", "set_robust_list", "get_robust_list",
  "seccomp",
  "landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self",
];

// @rule:KOS-003 trust_mask → additional syscalls (monotone — never subtract from baseline)
// Each entry: bit position → array of extra syscalls beyond baseline
export const TRUST_MASK_EXTRA_SYSCALLS: Record<number, string[]> = {
  // bit 0: auth — credential file ops
  0: ["keyctl", "add_key", "request_key"],
  // bit 1: rbac — identity service ops
  1: ["capget", "capset"],
  // bit 2: events — extended IPC
  2: ["eventfd", "eventfd2", "signalfd", "signalfd4", "timerfd_create", "timerfd_settime", "timerfd_gettime"],
  // bit 3: db — Unix socket + mmap for DB files
  3: ["flock", "shmget", "shmat", "shmdt", "shmctl"],
  // bit 4: notification — extended send
  4: ["sendfile", "splice", "tee"],
  // bit 5: cache — shared memory extended
  5: ["mlock", "munlock", "mlockall", "munlockall", "mremap"],
  // bit 6: registered — no extra syscalls needed
  6: [],
  // bit 7: forja — TLS needs extra ops
  7: ["memfd_create", "memfd_secret"],
  // bit 8: llm — large memory allocations
  8: ["mmap2"],
  // bit 9: knowledge — inotify for hot-reload
  9: ["inotify_init1", "inotify_add_watch", "inotify_rm_watch", "inotify_init"],
  // bit 10: domain_rules — no extra (rule eval is pure compute)
  10: [],
  // bit 11: memory — extended memory management
  11: ["remap_file_pages", "mbind", "get_mempolicy", "set_mempolicy"],
  // bit 12: search — no extra
  12: [],
  // bit 13: packages — npm/bun install ops
  13: ["symlink", "symlinkat", "link", "linkat"],
  // bit 14: swarm — extra process control
  14: ["kill", "tgkill", "tkill", "setpgid", "setsid", "getpgid", "getsid"],
  // bit 15: codegen — exec permission for generated code
  15: ["execveat"],
};

// Domain-specific extra syscalls (beyond trust_mask baseline)
export const DOMAIN_EXTRA_SYSCALLS: Record<string, string[]> = {
  general: [],
  maritime: [
    // NMEA serial port ops
    "ioctl",  // already in baseline via Bun, but domain flag makes it explicit
    "tcsendbreak", "tcdrain", "tcflush", "tcflow",
  ],
  logistics: [
    // EDI file processing — extended file ops already in baseline
  ],
  ot: [
    // OT/ICS — Modbus TCP, NMEA, AIS
    "ioctl",
    "sched_setscheduler", "sched_getscheduler", "sched_setparam", "sched_getparam",
  ],
  finance: [
    // HSM / hardware key ops
    "ioctl",
  ],
};

// @rule:INF-KOS-001 trust_mask=0 → read-only minimal profile (no exec, no network writes)
export const MINIMAL_READONLY_SYSCALLS: string[] = [
  "read", "open", "openat", "close", "stat", "fstat", "lstat", "newfstatat",
  "mmap", "munmap", "mprotect", "brk",
  // NO-FREEZE CRITICAL (must match BASELINE_SYSCALLS — never remove)
  "exit_group", "exit", "futex", "rt_sigreturn", "restart_syscall",
  "getpid", "gettid", "getcwd", "getdents64",
  "readlink", "readlinkat",
  "access", "faccessat",
  "gettimeofday", "clock_gettime",
  "arch_prctl", "set_tid_address", "set_robust_list",
  "rt_sigaction", "rt_sigprocmask",
  "clone3",  // Bun/Node thread creation — absent = silent hang on worker_threads
  "write",   // stdout/stderr only — Falco monitors for unexpected fds
];

// @rule:KOS-028 NOTIFY tier — pause, ask operator, then ALLOW or DENY
// These syscalls are uncommon but sometimes legitimately needed mid-run.
// They get SCMP_ACT_NOTIFY instead of SCMP_ACT_ERRNO so the agent waits
// for a human decision rather than dying with EPERM.
// Syscalls already in the ALLOW set (baseline + trust_mask extras) take
// precedence — the profile generator filters duplicates before writing NOTIFY rules.
export const NOTIFY_SYSCALLS: string[] = [
  "ptrace",          // process tracing / debugger attach
  "bpf",             // BPF program loading
  "mount", "umount2",// filesystem mounting
  "userfaultfd",     // userspace page-fault handler
  "perf_event_open", // performance monitoring
  "setns",           // namespace joining
  "capset",          // capability modification (also granted by trust bit 1)
];

// @rule:KOS-096 at depth≥4 these write-class syscalls move from ALLOW → NOTIFY tier
// The agent's writes are supervised; a kernel notifier must approve each one.
// read/stat/exit/futex stay in ALLOW so the agent can receive+surface operator instructions.
export const DEPTH4_SUPERVISED_SYSCALLS: string[] = [
  "write",     // any fd write — Falco context is lost at depth≥4, so every write is gated
  "writev",    // scatter-gather write
  "pwrite64",  // positional write
  "clone3",    // thread spawn — potential exfil via side-channel
];

// @rule:KOS-092 seccomp profile derived from (trust_mask, domain, delegation_depth) triplet
// @rule:KOS-093 depth reduction schedule — deeper delegation → narrower syscall surface
//   depth 1: full trust_mask set (no reduction)
//   depth 2: subtract ptrace + mknod* (debug/node-creation vectors closed)
//   depth 3: subtract clone + fork + clone3 (process spawning closed)
//   depth 4+: MINIMAL_READONLY_SYSCALLS regardless of trust_mask
export const DEPTH_REDUCTION_SCHEDULE: Record<number, string[]> = {
  2: ["ptrace", "mknod", "mknodeat"],
  3: ["clone", "fork", "clone3"],
};

export function buildSyscallSet(trustMask: number, domain: string, depth: number = 1): string[] {
  // depth 4+: absolute read-only regardless of trust_mask (KOS-093)
  if (depth >= 4) return [...new Set(MINIMAL_READONLY_SYSCALLS)];

  // trust_mask=0 → absolute minimal (INF-KOS-001)
  if (trustMask === 0) return [...new Set(MINIMAL_READONLY_SYSCALLS)];

  const set = new Set(BASELINE_SYSCALLS);

  // Add syscalls for each set trust_mask bit
  for (let bit = 0; bit < 16; bit++) {
    if (trustMask & (1 << bit)) {
      const extras = TRUST_MASK_EXTRA_SYSCALLS[bit] ?? [];
      extras.forEach((s) => set.add(s));
    }
  }

  // Add domain-specific syscalls
  const domainExtras = DOMAIN_EXTRA_SYSCALLS[domain] ?? DOMAIN_EXTRA_SYSCALLS.general;
  domainExtras.forEach((s) => set.add(s));

  // Apply depth reduction schedule (KOS-093)
  // depth 2: remove ptrace/mknod; depth 3: also remove clone/fork/clone3
  for (let d = 2; d <= Math.min(depth, 3); d++) {
    const toRemove = DEPTH_REDUCTION_SCHEDULE[d] ?? [];
    toRemove.forEach((s) => set.delete(s));
  }

  return [...set].sort();
}
