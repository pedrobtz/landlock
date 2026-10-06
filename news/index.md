# Changelog

## landlock 0.1.0

First release.

- A drop-in replacement for the ‘unix’ package: all 32 of its exports,
  with the same names, arguments and results
  ([`eval_safe()`](https://pedrobtz.github.io/landlock/reference/eval_safe.md),
  [`eval_fork()`](https://pedrobtz.github.io/landlock/reference/eval_safe.md),
  the `rlimit_*()` family, the process and id functions,
  [`user_info()`](https://pedrobtz.github.io/landlock/reference/userinfo.md),
  [`group_info()`](https://pedrobtz.github.io/landlock/reference/userinfo.md),
  [`chroot()`](https://pedrobtz.github.io/landlock/reference/chroot.md),
  [`sys_config()`](https://pedrobtz.github.io/landlock/reference/sys_config.md),
  [`aa_config()`](https://pedrobtz.github.io/landlock/reference/sys_config.md)).
  `eval_safe(profile =)` changes the AppArmor profile through `/proc`,
  without ‘libapparmor’.

- [`eval_safe()`](https://pedrobtz.github.io/landlock/reference/eval_safe.md)
  gains a `policy` argument;
  [`run()`](https://pedrobtz.github.io/landlock/reference/run.md)
  executes a program under one;
  [`confine()`](https://pedrobtz.github.io/landlock/reference/apply_policy.md)
  applies one to the session.

- Policies are built with
  [`policy()`](https://pedrobtz.github.io/landlock/reference/policy.md),
  [`fs()`](https://pedrobtz.github.io/landlock/reference/policy.md),
  [`net()`](https://pedrobtz.github.io/landlock/reference/policy.md),
  [`scope()`](https://pedrobtz.github.io/landlock/reference/policy.md),
  [`syscalls()`](https://pedrobtz.github.io/landlock/reference/policy.md),
  [`caps()`](https://pedrobtz.github.io/landlock/reference/policy.md),
  [`limits()`](https://pedrobtz.github.io/landlock/reference/policy.md),
  [`ids()`](https://pedrobtz.github.io/landlock/reference/policy.md) and
  [`apparmor()`](https://pedrobtz.github.io/landlock/reference/policy.md),
  or started from `preset("numeric")`, `preset("install")` and
  `preset("plumber")`. Layers:

  - Landlock filesystem rules, TCP port rules (kernel ABI 4) and scopes
    (ABI 6);
  - a seccomp-bpf system call filter, with the sets `"dangerous"`,
    `"no_exec"` and `"no_net"`;
  - capability dropping and `no_new_privs`;
  - resource limits and user switching.

- A layer the kernel cannot provide is skipped and reported
  ([`last_report()`](https://pedrobtz.github.io/landlock/reference/last_report.md));
  `policy(best_effort = FALSE)` makes it an error.
  [`status()`](https://pedrobtz.github.io/landlock/reference/status.md)
  shows what the running kernel offers.

- Single-layer functions for the calling process:
  [`restrict_self()`](https://pedrobtz.github.io/landlock/reference/restrict_self.md),
  [`seccomp_deny()`](https://pedrobtz.github.io/landlock/reference/seccomp_deny.md),
  [`caps_drop_all()`](https://pedrobtz.github.io/landlock/reference/caps_drop_all.md),
  [`caps_keep()`](https://pedrobtz.github.io/landlock/reference/caps_drop_all.md),
  [`no_new_privs()`](https://pedrobtz.github.io/landlock/reference/caps_drop_all.md),
  [`setids()`](https://pedrobtz.github.io/landlock/reference/setids.md).
