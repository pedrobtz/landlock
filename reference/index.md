# Package index

## Evaluate and run in a confined child

- [`eval_safe()`](https://pedrobtz.github.io/landlock/reference/eval_safe.md)
  [`eval_fork()`](https://pedrobtz.github.io/landlock/reference/eval_safe.md)
  : Evaluate in a forked, optionally confined, child process
- [`run()`](https://pedrobtz.github.io/landlock/reference/run.md) : Run
  a program in a confined child process
- [`last_report()`](https://pedrobtz.github.io/landlock/reference/last_report.md)
  : The report of the last enforcement

## Policies

Describe what the child may do. Policies are plain data.

- [`policy()`](https://pedrobtz.github.io/landlock/reference/policy.md)
  [`fs()`](https://pedrobtz.github.io/landlock/reference/policy.md)
  [`net()`](https://pedrobtz.github.io/landlock/reference/policy.md)
  [`scope()`](https://pedrobtz.github.io/landlock/reference/policy.md)
  [`limits()`](https://pedrobtz.github.io/landlock/reference/policy.md)
  [`ids()`](https://pedrobtz.github.io/landlock/reference/policy.md)
  [`apparmor()`](https://pedrobtz.github.io/landlock/reference/policy.md)
  [`syscalls()`](https://pedrobtz.github.io/landlock/reference/policy.md)
  [`caps()`](https://pedrobtz.github.io/landlock/reference/policy.md) :
  Build a confinement policy
- [`preset()`](https://pedrobtz.github.io/landlock/reference/preset.md)
  : Ready-made policies
- [`apply_policy()`](https://pedrobtz.github.io/landlock/reference/apply_policy.md)
  [`confine()`](https://pedrobtz.github.io/landlock/reference/apply_policy.md)
  : Apply a policy

## What this kernel offers

- [`status()`](https://pedrobtz.github.io/landlock/reference/status.md)
  : What this kernel offers

## Single layers, on the calling process

Irreversible. Use them inside eval_safe() or in a process you own.

- [`restrict_self()`](https://pedrobtz.github.io/landlock/reference/restrict_self.md)
  : Restrict this process with Landlock
- [`seccomp_deny()`](https://pedrobtz.github.io/landlock/reference/seccomp_deny.md)
  [`seccomp_status()`](https://pedrobtz.github.io/landlock/reference/seccomp_deny.md)
  [`syscall_table()`](https://pedrobtz.github.io/landlock/reference/seccomp_deny.md)
  : System call filters
- [`caps_drop_all()`](https://pedrobtz.github.io/landlock/reference/caps_drop_all.md)
  [`caps_keep()`](https://pedrobtz.github.io/landlock/reference/caps_drop_all.md)
  [`no_new_privs()`](https://pedrobtz.github.io/landlock/reference/caps_drop_all.md)
  : Capabilities and no_new_privs
- [`setids()`](https://pedrobtz.github.io/landlock/reference/setids.md)
  : Switch user and group
- [`chroot()`](https://pedrobtz.github.io/landlock/reference/chroot.md)
  : Change root directory

## Process, limits and ids (the ‘unix’ API)

The functions of the ‘unix’ package, with the same names and arguments.

- [`rlimit_all()`](https://pedrobtz.github.io/landlock/reference/rlimit.md)
  [`rlimit_as()`](https://pedrobtz.github.io/landlock/reference/rlimit.md)
  [`rlimit_core()`](https://pedrobtz.github.io/landlock/reference/rlimit.md)
  [`rlimit_cpu()`](https://pedrobtz.github.io/landlock/reference/rlimit.md)
  [`rlimit_data()`](https://pedrobtz.github.io/landlock/reference/rlimit.md)
  [`rlimit_fsize()`](https://pedrobtz.github.io/landlock/reference/rlimit.md)
  [`rlimit_memlock()`](https://pedrobtz.github.io/landlock/reference/rlimit.md)
  [`rlimit_nofile()`](https://pedrobtz.github.io/landlock/reference/rlimit.md)
  [`rlimit_nproc()`](https://pedrobtz.github.io/landlock/reference/rlimit.md)
  [`rlimit_stack()`](https://pedrobtz.github.io/landlock/reference/rlimit.md)
  : Resource limits
- [`getuid()`](https://pedrobtz.github.io/landlock/reference/process.md)
  [`getgid()`](https://pedrobtz.github.io/landlock/reference/process.md)
  [`geteuid()`](https://pedrobtz.github.io/landlock/reference/process.md)
  [`getegid()`](https://pedrobtz.github.io/landlock/reference/process.md)
  [`getpid()`](https://pedrobtz.github.io/landlock/reference/process.md)
  [`getppid()`](https://pedrobtz.github.io/landlock/reference/process.md)
  [`getpgid()`](https://pedrobtz.github.io/landlock/reference/process.md)
  [`getpriority()`](https://pedrobtz.github.io/landlock/reference/process.md)
  [`setuid()`](https://pedrobtz.github.io/landlock/reference/process.md)
  [`seteuid()`](https://pedrobtz.github.io/landlock/reference/process.md)
  [`setgid()`](https://pedrobtz.github.io/landlock/reference/process.md)
  [`setegid()`](https://pedrobtz.github.io/landlock/reference/process.md)
  [`setpgid()`](https://pedrobtz.github.io/landlock/reference/process.md)
  [`setpriority()`](https://pedrobtz.github.io/landlock/reference/process.md)
  [`kill()`](https://pedrobtz.github.io/landlock/reference/process.md) :
  Process information
- [`user_info()`](https://pedrobtz.github.io/landlock/reference/userinfo.md)
  [`group_info()`](https://pedrobtz.github.io/landlock/reference/userinfo.md)
  : User and group information
- [`aa_config()`](https://pedrobtz.github.io/landlock/reference/sys_config.md)
  [`sys_config()`](https://pedrobtz.github.io/landlock/reference/sys_config.md)
  : Package configuration
- [`aa_change_profile()`](https://pedrobtz.github.io/landlock/reference/aa_change_profile.md)
  : Change AppArmor profile
