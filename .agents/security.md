# Security review, Stage 5 (2026-10-06)

An independent read-only review of the C core (`src/*.c`, `src/compat/`), the
R adapter (`src/rglue.c`) and the R engine (`R/apply.R`, `R/eval_safe.R`,
`R/presets.R`, `R/seccomp.R`, `R/caps.R`) on branch `stage-5-hardening`. Every
finding below was checked against the code before it was fixed. Each fix has
a regression test, named in the last column.

The threat model: code evaluated under a `policy` is hostile. It runs in a
forked child after the policy is applied, and it may write anything to the
file descriptors it holds, the result pipe included. Code evaluated without a
policy (`eval_fork()`, `eval_safe()` with only the `unix` arguments) is
trusted, as in `unix`.

| # | Severity | Finding | Resolution | Test |
|---|---|---|---|---|
| 1 | high | The session unserialized the child's payload and read fields with `$`. Confined code can call `.Call(C_write_frame)` and send a frame of its own first; an environment with an active binding named `ok` or `report` then runs code in the unconfined session. | Under a policy the outcome must be a plain list (`typeof() == "list"`, not an object); fields are read with `.subset2()`; the report and the error condition are rebuilt from plain character fields (`read_outcome()`, `read_report()`, `read_condition()`). The returned value is the caller's data and `?eval_safe` says it is untrusted. Without a policy nothing changes (trusted code, `unix` parity). | `test-security.R`: forged frame, forged error |
| 2 | medium | fd hygiene failed open: `lk_close_from()` fell back to listing `/proc/self/fd` only on `ENOSYS`/`EINVAL`, and the child ignored its result and that of the stdin/stdout redirections. A filter that refuses `close_range` with `EPERM` left every inherited fd open under Landlock. | Inherited descriptors are no longer closed but pointed at `/dev/null` (close-on-exec) after a full listing, with no `close_range` path to fail. Closing had a second defect found by `R CMD check`'s examples: R objects inherited from the session (the example `pdf()` device) still held the numbers, the child's sink reused one, and `graphics.off()` wrote the PDF into captured output. A child whose setup fails writes an `F` frame and ends before any user code; the session raises "child process setup failed". | `test-hardening.R`: descriptors under a policy, session graphics device |
| 3 | medium | Presets granted read-write on the session's `tempdir()`, so confined code could plant files the session later trusts (cached shared libraries from `Rcpp::sourceCpp`, knitr caches, `.rds`). | `fs(tmp = TRUE)` grants the call's own scratch directory (`tmp`, the child's `TMPDIR`), which is created with mode 0700 and removed after the call when left at its default. Presets use it; `tempdir()` is no longer granted. | `test-security.R`: scratch directory, presets |
| 4 | medium | Deny-list gaps: `clone()`/`clone3()` with `CLONE_NEW*` bypassed the `unshare`/`setns` deny; `socketcall` (i386) bypassed `no_net`; `pidfd_getfd`, `setsid` were allowed. | Denying `unshare` adds a BPF check refusing `clone()` with any `CLONE_NEW*` flag (flags at `args[0]`, `args[1]` on s390x, low word at +4 on big-endian). `clone3` always gets `ENOSYS` so glibc falls back to the inspectable `clone()`. `socketcall` joins `no_net`; `clone3`, `pidfd_getfd`, `setsid`, `setpgid` join `dangerous`. | `test-security.R`: clone, clone3, sets |
| 5 | medium | Root switching uid without a gid kept gid 0 and its supplementary groups; negative or out-of-range ids silently meant "skip". | A uid without a gid takes the user's primary group; `lk_setids()` also clears the supplementary groups when root switches uid alone. Ids must be whole numbers from 0 to `.Machine$integer.max`. | `test-security.R`: ids, root drops groups |
| 6 | low-medium | The result pipe was buffered without bound: a child could exhaust the session's memory. | Capped at `getOption("landlock.max_result", 2^31)` bytes; beyond it the child is killed and the call fails. stdout/stderr were already streamed to callbacks. | `test-security.R`: size cap |
| 7 | low | `kill(-pid)` after reaping could reach a process group that reused the number. | `lk_wait_collect()` detects the exit with `waitid(WNOWAIT)`, kills the group while the zombie still pins its id, then reaps; `*done` is set before any drain error; `kill_child()` never acts after reaping. | `test-hardening.R`: grandchildren |
| 8 | low | `R_MakeUnwindCont()` allocated after `fork()`: an allocation error in the child would have longjmp'd into a copy of the session's toplevel. | Both continuations are allocated and protected before `fork()`. | (no deterministic test) |
| 9 | low | `limits(memory = "1.5.g")` parsed to `NA`, which became "unlimited". | `parse_size()` rejects anything that does not parse; `apply_policy()` rejects `NA` limits. | `test-security.R`: sizes |
| 10 | low | `parse_frames()` indices overflowed past 2^31 bytes; the testing option `landlock.force_abi` accepted any value (a non-number became `INT_MIN`, i.e. "no Landlock"); the scratch directory was never removed. | Double indices; the option is honoured only as a whole number from -1 to 7, with a warning otherwise; the default scratch directory is removed. On the option: code that can set options in the session is already unconfined, so this is about mistakes, not attacks. | `test-security.R`: option, scratch directory |

## Accepted, documented

- **Values returned from confined code are untrusted.** They can contain
  closures, or environments whose active bindings run code when read
  (`lm` objects carry environments, so rejecting environments is not an
  option). The package never evaluates them; the caller is told to return
  plain data (`?eval_safe`, Value).
- **`unserialize()` is not hardened against hostile input.** A crafted
  stream can reach ALTREP class methods of packages loaded in the session.
  Mitigation for later: a "data only" result mode that transfers a
  restricted format instead of R serialization.
- **Landlock `EXECUTE` does not cover `mmap(PROT_EXEC)`.** Confined code
  that can write a shared library to a writable directory can load it. The
  seccomp layer still applies to it; presets deny `execve` where possible.

## Checked and found sound

Landlock rights per ABI and the ruleset size per ABI; file-rule masking;
net and scope gating by ABI; strict mode; `no_new_privs` before
`restrict_self`; seccomp arch check, x32 guard and jump offsets; unknown
architectures refused rather than filtered without an arch check; TSYNC
fallback reported; capability ordering around `setids`; `apply_policy()`
order against design section 4; collect-loop buffer arithmetic; pipes
close-on-exec; PROTECT balance in `rglue.c`; no `exit`/`_exit`/`abort`/
`printf`/`stdout` symbols and no non-API entry points.
