# landlock 0.1.0

First release.

* A drop-in replacement for the 'unix' package: all 32 of its exports, with
  the same names, arguments and results (`eval_safe()`, `eval_fork()`, the
  `rlimit_*()` family, the process and id functions, `user_info()`,
  `group_info()`, `chroot()`, `sys_config()`, `aa_config()`).
  `eval_safe(profile =)` changes the AppArmor profile through `/proc`,
  without 'libapparmor'.

* `eval_safe()` gains a `policy` argument; `run()` executes a program under
  one; `confine()` applies one to the session.

* Policies are built with `policy()`, `fs()`, `net()`, `scope()`,
  `syscalls()`, `caps()`, `limits()`, `ids()` and `apparmor()`, or started
  from `preset("numeric")`, `preset("install")` and `preset("plumber")`.
  Layers:
  * Landlock filesystem rules, TCP port rules (kernel ABI 4) and scopes
    (ABI 6);
  * a seccomp-bpf system call filter, with the sets `"dangerous"`,
    `"no_exec"` and `"no_net"`;
  * capability dropping and `no_new_privs`;
  * resource limits and user switching.

* A layer the kernel cannot provide is skipped and reported
  (`last_report()`); `policy(best_effort = FALSE)` makes it an error.
  `status()` shows what the running kernel offers.

* Single-layer functions for the calling process: `restrict_self()`,
  `seccomp_deny()`, `caps_drop_all()`, `caps_keep()`, `no_new_privs()`,
  `setids()`.
