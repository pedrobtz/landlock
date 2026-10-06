# Roadmap: landlock 0.1.0 to CRAN

Companion to [design.md](design.md). Written 2026-10-06 against commit
`eb37416` (package skeleton + pkgdown). Tick boxes as work lands; when a stage's
exit criteria hold, move on. Dates are deliberately absent: the order and the
exit criteria are the contract, not the calendar.

| Stage | Outcome | Depends on |
|---|---|---|
| 0 | 0.1.0 scope fixed, design.md corrected | — |
| 1 | Repo hygiene, Linux dev loop, r-actions CI green on the skeleton | 0 |
| 2 | C core for Landlock, rlimits, ids, process plumbing; C harness green without R | 1 |
| 3 | R layer: the full `unix` API, `status()`, policy object, `eval_safe()`, `run()`, `confine()` | 2 |
| 4 | seccomp and capabilities, C and R | 3 |
| 5 | Hardening: interrupts, zombies, fd leaks, every native-checks leg green, arch legs, security review | 4 |
| 6 | Documentation: reference, README, vignettes, NEWS, pkgdown | 5 |
| 7 | CRAN readiness: clean `--as-cran` on every CRAN flavour, cran-comments | 6 |
| 8 | Submission, review loop, release 0.1.0, start 0.1.0.9000 | 7 |

---

## Stage 0 — Fix the scope and the design

### 0.1 What 0.1.0 contains

Design milestones M1 and M2, plus fd hygiene pulled forward from M4. Everything
in this list works unprivileged, inside Docker, and on CRAN's check machines,
which is what makes a first review tractable.

- **The complete `unix` 1.6.0 API** (design §15), as first-class exports with
  identical formals: `eval_safe`, `eval_fork`, the nine `rlimit_*` functions
  and `rlimit_all`, `getuid`/`geteuid`/`getgid`/`getegid` and their setters,
  `getpid`, `getppid`, `getpgid`, `setpgid`, `kill`, `getpriority`,
  `setpriority`, `user_info`, `group_info`, `chroot`, `sys_config`,
  `aa_config`. `eval_safe(profile=)` works through a `/proc` write. `unix`'s
  own test files are ported and must pass. This is the headline of 0.1.0: a
  user replaces `library(unix)` with `library(landlock)` and nothing changes
  until they pass a `policy`.
- `status()` with the full probe table from design §7 (namespace and cgroup
  probes included: they are cheap and show users what 0.2.0 will unlock).
- Policy builder: `policy()`, `fs()`, `net()`, `syscalls()`, `caps()`,
  `limits()`, `ids()`, `options()`; `print()` for `lk_policy`.
- Engine: `apply_policy()`, `confine()`.
- Execution: `eval_safe()`, `eval_fork()`, `run()` (fork, restrict, exec; no
  pid namespace).
- Thin wrappers: `restrict_self()`, `seccomp_deny()`, `seccomp_status()`,
  `syscall_table()`, `caps_drop_all()`, `caps_keep()`, `no_new_privs()`,
  `setids()`.
- Presets as R objects in `R/presets.R` (not TOML): syscall sets `dangerous`,
  `no_exec`, `no_net`; policy presets `numeric`, `install`, `plumber`.
- fd hygiene in the child before restriction (design §11): without it Landlock
  has a documented hole from day one, and it is ~40 lines of C.

### 0.2 What waits for 0.2.0 and later

- Namespaces, mounts, hostname (M3). Host-policy dependent (AppArmor on Ubuntu
  ≥ 24.04, Docker's default seccomp profile); the one layer whose tests cannot
  be made deterministic across CRAN flavours.
- `run()` pid-namespace double fork (M3).
- cgroup v2 layer, streaming stdout (M4). `limits(memory=)` maps to
  `RLIMIT_AS` only in 0.1.0; document the OpenBLAS caveat.
- TOML policies, `read_policy()`, `write_policy()`, `explain()`, `trace()` (M5).
- The shipped `inst/apparmor` userns profile (the `profile=` argument itself
  is 0.1.0, see 0.1).
- `namespaces()` and `mounts()` are not exported in 0.1.0 at all. Reserving a
  verb that errors "not implemented" is worse for CRAN review than absence.

### 0.3 Corrections to design.md before coding starts

Each of these was found while reviewing the document against the skeleton,
the `unix` sources and CRAN policy. Apply them to design.md so it stays the
source of truth.

- [x] **Naming leftovers.** §5 still uses the `BRIG_*` enum prefix
  (`BRIG_LL_READ`, `BRIG_SC_ERRNO`, `BRIG_NS_USER`). §16 decided on `lk_`; use
  `LK_*` for enums and macros throughout.
- [x] **Inconsistent names across sections.** §12 tests write
  `status()$landlock > 0` while §6.2 names the field `landlock_abi`; §14 (M1)
  still says `landlock()` where §16 renamed it `restrict_self()`. Pick
  `landlock_abi` and `restrict_self()` everywhere.
- [x] **`eval_safe()` is not actually unix-compatible.** The real signature is
  `unix::eval_safe(expr, tmp = tempfile("fork"), std_out = stdout(), std_err = stderr(), timeout = 0, priority = NULL, uid = NULL, gid = NULL, rlimits = NULL, profile = NULL, device = pdf)`.
  The design puts `policy` second, drops `tmp`, `profile` and `device`, and
  reorders the rest, so any positional call breaks. Decision: keep unix's
  argument list verbatim and append `policy = NULL` as the last named
  argument. `tmp` is honoured as the child's temp directory as in unix.
  `profile` errors unless `NULL` in 0.1.0 (AppArmor deferred). `device` is
  applied in the child.
- [x] **How the child exits.** `_exit()` in compiled code triggers the
  `R CMD check` NOTE "compiled code should not call entry points which might
  terminate R". `unix` avoids it: the child closes its pipe write ends and
  calls `raise(SIGKILL)`. Decision for 0.1.0: do the same. Consequence for
  §6.3: the parent cannot use "killed by signal" alone to mean failure. The
  discriminator is the result pipe: a complete serialized payload means a
  normal exit regardless of the wait status; SIGKILL with an empty or
  truncated payload means timeout, seccomp `kill`, or OOM. Rewrite that
  branch of the engine description.
- [x] **Non-Linux builds.** CRAN checks on macOS. Every Linux-only function
  in `ll.c`, `sc.c`, `caps.c` is wrapped `#ifdef __linux__ … #else return
  -ENOSYS; #endif`; `lk.h` declares everything on every platform; `status()`
  reports zeros; `lim.c` and `proc.c` are plain POSIX. No `configure` script.
  `OS_type: unix` keeps Windows out of CRAN's matrix. Say this in §3 and §13.
- [x] **Interruptibility.** `lk_wait_collect()` as specified blocks in
  `poll()` for the whole timeout, so Ctrl-C in the parent is dead until the
  child finishes. Give it a slice length (200 ms) and loop in `rglue.c`,
  calling `R_CheckUserInterrupt()` between slices; on interrupt, SIGKILL the
  child, drain, `waitpid`, then rethrow. Handle `EINTR` from `poll()`.
- [x] **fd hygiene moves to M1** (see 0.1). `close_range(2)` when available,
  else iterate `/proc/self/fd` (Linux) or `/dev/fd` (macOS); keep 0, 1, 2 and
  the pipe write ends.
- [x] **Copyright of vendored uapi constants.** `LICENSE.note` is the
  design's answer; CRAN's answer is a `Copyright:` field or `cph` entries in
  `Authors@R`. Add `inst/COPYRIGHTS` (Linux kernel uapi headers, GPL-2.0 WITH
  Linux-syscall-note, user-space use permitted) and `Copyright: file
  inst/COPYRIGHTS` in DESCRIPTION, plus the existing `LICENSE.note`.
- [x] **Tests that cannot run on CRAN.** Add to §12: nothing one-way ever
  runs in the check process, only in a forked child; every timeout in tests is
  ≤ 2 s; zombie checks use `kill(pid, 0)` returning `ESRCH` rather than
  shelling out to `ps` (no `/proc` on macOS); skips are driven by `status()`
  fields, never by `Sys.info()`.
- [x] **CI.** The reusable workflow's default runner matrix includes
  `windows-latest`; an `OS_type: unix` package cannot install there. Override
  `runners` without that row. The runner job runs as a non-root user and the
  container job runs as root, which gives the root/non-root split design §12
  asks for without extra jobs.
- [x] **Coverage.** gcov counters are flushed at process exit and R-level
  trace counters live in the child's memory, so with `raise(SIGKILL)` every
  line executed in the child reports as uncovered. Expect the badge to
  undercount; do not gate on it. (Optional later: `__gcov_dump()` before the
  kill under a compile flag.)
- [x] **DESCRIPTION text.** CRAN asks for software names in single quotes and
  a reference for the method: 'Landlock', 'seccomp', 'unix', and
  `<https://landlock.io/>` in Description.
- [x] **Replacement, not superset.** The package replaces `unix`: all 32
  exports with identical formals are 0.1.0 scope, `unix`'s tests are ported,
  `profile=` is honoured through `/proc`. Design §1, §3, §5.5, §6.2, §13, §15
  updated; the `compat-unix.R` side file is gone.
- [x] **CI through r-actions from the start.** `R-CMD-check`, `coverage`
  (`native: true`), `native-checks` (seven jobs), `arch` (i386, musl,
  aarch64) and a hand-written `c-harness` workflow are in `.github/workflows/`.
  Design §12 carries the table. Consequence recorded there: tests must
  tolerate the 10–50× slowdown of the valgrind, ASan and gctorture legs, so no
  tight wall-clock assertions.
- [x] **seccomp on i386 and arm.** The design's arch list lacked them; the
  `arch` workflow would have failed on its first default leg. §5.2 now lists
  `__i386__` and `__arm__` and returns `-ENOTSUP` elsewhere.

Exit criteria: design.md updated and committed; `.agents/roadmap.md` (this
file) reflects the same decisions.

---

## Stage 1 — Foundations

Goal: a repository where `R CMD check` and the C harness can both run, on a
Linux box, from the first real commit.

### Repo hygiene

- [x] `.Rbuildignore`: `^\.agents$`, `^tests/c$`, `^cran-comments\.md$`,
      `^CRAN-SUBMISSION$`, `^LICENSE\.note$`. (`.agents/` is a hidden
      directory; without this `R CMD check` emits the hidden-files NOTE.)
- [x] DESCRIPTION: real `Authors@R` (name, email, ORCID if any), Title and
      Description from design §13 with the Stage 0 wording fixes, `OS_type:
      unix`, `SystemRequirements: Linux kernel >= 5.13 for Landlock; seccomp
      and capabilities need Linux; resource limits and fork work on any
      Unix-alike`, `BugReports: https://github.com/pedrobtz/landlock/issues`,
      `Copyright: file inst/COPYRIGHTS`. Keep `Version: 0.0.0.9000` until
      Stage 8. Imports only base packages. The maintainer is Pedro Baltazar,
      as on the CRAN package `zujson` (the first draft had `Pedro Z` from the
      GitHub profile; corrected in Stage 6). Jeroen Ooms is `cph` for the ported `unix` tests.
- [x] `LICENSE`: kept as "landlock authors". That is the usethis convention
      CRAN accepts for `MIT + file LICENSE`; the people are in `Authors@R`.
- [x] `LICENSE.note` and `inst/COPYRIGHTS` for the uapi constants and the
      ported `unix` tests (MIT notice reproduced in full).
- [x] Delete `src/landlock.c` (stub); create `src/Makevars`
      (`PKG_CPPFLAGS = -I. -D_GNU_SOURCE`), `src/lk.h`, `src/compat/`,
      `src/init.c`, `src/rglue.c`. They carry one real function,
      `lk_ll_abi()` with its `.Call` adapter, because an empty `.so` fails the
      sanitizers workflow's "was this build instrumented?" check: UBSan has
      nothing to instrument in a file with no code.
- [x] `NAMESPACE` regenerated by roxygen (`useDynLib(landlock, .registration
      = TRUE)`), `man/landlock-package.Rd` created, `R_useDynamicSymbols(dll,
      FALSE)` in `init.c`.
- [x] `tests/c/Makefile` + `run.c` harness: each test in its own forked
      child, suites registered in `suites.h`, `-Werror` always on, `CFLAGS`
      overridable for the clang leg. Prints the Landlock ABI and uid first.
- [x] `tools/gen_syscalls.sh` + `tools/syscalls.txt` + committed
      `src/sc_table.h` (242 names, sentinel-terminated; compiled from Stage 4).

### Linux dev loop (the workstation is macOS)

Landlock, seccomp and capabilities do not exist on the Mac. Written up in
`.agents/dev-env.md`; CI is the reference Linux environment because the local
podman VM does not start.

- [x] Docker Desktop / OrbStack / colima with `rocker/r-ver:4.5` for the R
      side and `ubuntu:24.04` for the bare C harness. Default Docker seccomp
      allows the `landlock_*` and `seccomp` syscalls, so M1 and M2 are fully
      testable in a container. Confirm with `status()` on first run: whether
      the VM kernel boots with the Landlock LSM enabled is the one thing a
      container cannot fix.
- [ ] Record the ABI the dev kernel reports. The design environment had
      kernel 6.18 (ABI 7); GitHub's `ubuntu-24.04` runners report ABI 4 or 5
      depending on the image kernel. ABI 6–7 code paths (scopes, log flags)
      need the newer kernel; keep that box around for manual runs.

### CI (`pedrobtz/r-actions`, see design §12 for the table)

- [x] `R-CMD-check.yaml`: `runners` overridden to macOS release, ubuntu
      release, ubuntu oldrel-1 (no Windows); containers at default.
- [x] `coverage.yaml` with `native: true`.
- [x] `native-checks.yaml`: sanitizers (ASan on), valgrind, lto, gctorture,
      rchk, analyzers, cran-special, with the quick/full profile expression.
- [x] `arch.yaml`: i386, musl and aarch64, weekly and on `workflow_dispatch`.
- [x] `c-harness.yaml`: the one hand-written job; builds `tests/c` on the VM
      runner (runner user and `nobody`) and in `ubuntu:24.04` (root, gcc and
      clang `-std=gnu23 -pedantic`). Its `paths` filter means it only runs
      when `src/` or `tests/c/` change. Until `tests/c/Makefile` exists its
      build steps are skipped with a notice, so the check is green on the
      skeleton without pretending to have run anything.
- [ ] First real run of `c-harness` once `tests/c` has a Makefile; remove
      nothing from the workflow, the gate switches itself.
- [x] Add the `full-ci` label to the repo so a PR can opt into the full
      profile.
- [x] Confirm the pkgdown workflow deploys the current skeleton to
      `https://pedrobtz.github.io/landlock/` so docs are live from day one.
- [x] Badges in README for R-CMD-check, coverage and native-checks.

Exit criteria: `R CMD check --as-cran` on the empty package is 0/0/0 on
macOS and Linux; `cd tests/c && make && ./run` passes with zero tests; every
workflow in `.github/workflows/` has run green at least once on `main`.

---

## Stage 2 — C core, M1

Goal: the reusable C library (design §5.1, §5.5, §5.6) proven by the harness,
with no R in sight.

- [x] `src/compat/landlock_compat.h`: every struct and constant through
      ABI 7 under `lk_`/`LK_` names, plus the `__NR_landlock_*` fallbacks
      (444–446). The system header is never included: its
      `struct landlock_ruleset_attr` lacks `scoped` and a struct cannot be
      `#ifndef`-guarded (design §10).
- [x] `ll.c`: `lk_ll_abi()` (done in Stage 1), `lk_ll_restrict()` per the §5.1 algorithm.
      Ruleset attr size computed from ABI (8/16/24 bytes), `ACCESS_FILE` mask
      for non-directories, rights table from §9, `no_new_privs` before
      `restrict_self`, best-effort masking versus `-ENOTSUP` in strict mode,
      report struct filled in.
- [x] `lim.c`: `lk_rlimit_lookup/get/set`, `lk_setids`, `lk_setid`,
      `lk_setpgid`, `lk_priority_get/set`, `lk_chroot`,
      `lk_aa_change_profile`. `RLIM_INFINITY` ↔ `UINT64_MAX`.
- [x] `proc.c`: `lk_fork`, `lk_pipe` (`O_CLOEXEC`), `lk_dup2`,
      `lk_write_all`, `lk_wait_collect` (poll loop with slice argument,
      `EINTR` handling, drains all fds, SIGKILL on timeout, `waitpid`),
      `lk_kill`, `lk_fd_hygiene` (fd hygiene; was `lk_close_from`, see security.md #2), `lk_child_exit` (close pipe
      write ends, `raise(SIGKILL)`).
- [x] `lk.h`: every prototype, `(void)` on empty parameter lists
      (`-Wstrict-prototypes` is on in R-devel checks), no R headers.
- [x] Error convention enforced: `0`/`-errno`, no `fprintf`, no `exit`, no
      globals.
- [x] Harness tests: `test_ll.c` (deny `/etc` read → `EACCES`; allow tempdir
      → ok; file-not-directory rule accepted; ABI 0 → report all zero, return
      0 in best-effort, `-ENOTSUP` strict), `test_lim.c` (`RLIMIT_NOFILE`
      lowered → `open` fails with `EMFILE`), `test_proc.c` (fork + pipe +
      timeout kill; 1 MiB child output does not deadlock; fd hygiene leaves
      only the kept fds).

Added beyond the plan: `force_abi` in the policy so the harness stacks one
domain per ABI level against the real kernel and tests the "absent" path on a
kernel that has Landlock; `failed_path` in the report; `lk_userns_works()`
for `status()`.

Exit criteria: harness green on the dev kernel as root and as `nobody`; the
same sources compile warning-free under `clang -std=gnu23 -pedantic` and
`gcc -Wall -Wextra -pedantic`; on macOS, `ll.c` compiles and `lk_ll_abi()`
returns 0.

---

## Stage 3 — R layer, M1

Goal: `unix`'s ported test suite passes against `landlock`, and
`eval_safe(readLines("/etc/passwd"), policy = preset("numeric"))` errors with
`EACCES`.

- [x] `rglue.c`: `.Call` wrappers for every `lk_*` entry point used by R;
      the only file including `Rinternals.h`. `init.c` registers them.
      Test-only helpers (`C_test_getppid` for Stage 4) registered too.
- [x] `R/status.R`: `status()` with every field from §7 (`/proc` and sysctl
      reads in R; `userns.works` via a forked probe child).
- [x] `R/policy.R`: builder verbs, `lk_policy` class, validation at build
      time (types, enum values), path existence checked at apply time only.
      `fs(rw=)` convenience (design §17.7). `print()` shows layers and whether
      the current kernel honours each.
- [x] `R/apply.R`: `apply_policy(p, strict = FALSE)` applying layers in the
      §4 order (steps 7, 9, 11, 12 in 0.1.0), returning an `lk_report`;
      `confine()` warns, or errors unless `force = TRUE`, when
      `/proc/self/task` has more than one entry (design §17.3: go with error).
- [x] The `unix` API, written against `unix` 1.6.0's formals one function at
      a time: `R/limits.R` (`rlimit_*(cur = NULL, max = NULL)`, `rlimit_all()`,
      `chroot(path = getwd())`), `R/process.R` (`getpid`, `getppid`, `getpgid`,
      `setpgid`, `kill`, `getpriority`, `setpriority`, `sys_config`),
      `R/ids.R` (the eight get/set uid/gid functions, `user_info`,
      `group_info`), `R/apparmor.R` (`aa_config`, `aa_change_profile`).
      `R/restrict.R` for `restrict_self()`.
- [x] Port `unix/tests/testthat/test-forking.R` and `test-process.R`
      verbatim (MIT, attribution in the file header) and make them pass.
      Add `test-unix-parity.R`: the 32-name constant from design §15 is a
      subset of `getNamespaceExports("landlock")`, and each function's
      `formals()` equals the recorded `unix` formals.
- [x] `R/eval_safe.R`: `eval_safe()` with the unix signature plus `policy`;
      `eval_fork()`; `run()` (fork, `apply_policy`, `execvp`, capture).
      Child side: `options(device = pdf)`, `tmp` honoured, fd hygiene,
      serialize `list(value=, report=)` or `list(error = <condition>)`.
      Parent side: interruptible wait, timeout → error, result-pipe
      discriminator for SIGKILL, stdout/stderr delivered to `std_out`/`std_err`
      (`NULL` discards).
- [x] `R/presets.R`: `preset("numeric")` etc. as R objects built from
      `.libPaths()`, `R.home()`, `tempdir()` at call time.
- [x] testthat (edition 3, `Config/testthat/parallel` left off because the
      tests fork): `status()` shape on every platform; `eval_safe(1 + 1)`
      with no policy on every platform including macOS; Landlock tests
      `skip_if(status()$landlock_abi == 0)`; timeout test (`Sys.sleep(5)`,
      `timeout = 1`) errors with elapsed under 10 s (valgrind and gctorture
      legs are slow) and `kill(pid, 0)` says `ESRCH`; pipe-deadlock regression
      (child writes 1 MiB); error objects cross the pipe as conditions;
      `strict = TRUE` errors on ABI 0.

Built differently from the plan, recorded in design §6.3 and §15: the
result pipe carries typed frames; the report goes to `last_report()` instead
of an attribute; `q()` in a child is caught by an exit finalizer; output is
captured with `sink()`; `tmp` becomes `TMPDIR` because `tempdir()` cannot be
switched without R internals. `unix` has 32 exports, not 31.

Exit criteria: the M1 definition of done from design §14 passes on every
r-actions leg that runs on a PR, the ported `unix` tests are green, and the
suite is green on the macOS runner (everything Linux-only skipped with a
reason).

---

## Stage 4 — seccomp and capabilities, M2

- [x] `tools/gen_syscalls.sh` produces `src/sc_table.h` from a plain name
      list (~160 names, each `#ifdef SYS_<name>`-guarded); commit the output.
- [x] `src/compat/seccomp_compat.h`, `src/compat/caps_compat.h`.
- [x] `sc.c`: table lookups, `lk_sc_status()`, `lk_sc_deny()` building the
      §5.2 BPF (arch check, x32 guard on x86_64, 2 instructions per syscall),
      TSYNC install with `EINVAL` fallback and prctl fallback.
- [x] `caps.c`: `lk_cap_last`, `lk_cap_lookup`, `lk_caps_drop_bounding`,
      `lk_caps_clear` (capset v3 + ambient clear), `lk_nnp_set/get`.
- [x] Harness: `test_sc.c` (deny `getppid` → `EPERM`; `kill` action kills
      the child with SIGSYS; filter rejected on wrong arch), `test_caps.c`
      (bounding set empty after drop; `CapEff` zero after clear).
- [x] `R/seccomp.R`, `R/caps.R`; `syscalls()` and `caps()` verbs wired into
      `apply_policy()` at steps 8 and 10 of §4; syscall presets.
- [x] testthat: `eval_safe(.Call(C_test_getppid), policy = policy() |>
      syscalls(deny = "getppid"))` surfaces `EPERM`; `action = "kill"` gives
      the "killed by signal" error; `preset("dangerous")` lets `1 + 1` and
      `lm()` run; `no_exec` makes `system("true")` fail; caps test
      `skip_if(status()$caps$effective == "0")` otherwise asserts the forked
      child's `CapBnd` is zero. All pass as the non-root runner user.

Built differently from the plan, recorded in design §4 and §5: capabilities
are two steps around `setids` (the bounding set at step 8, the sets at step
12); the syscall table names every call on every architecture, `-1` where
absent; the BPF definitions are vendored so musl needs no `linux/filter.h`;
capability names live in R. The kill test uses `getppid()` directly: with
an errno filter it returns `-1`, so no C test helper was needed.

Exit criteria: M2 definition of done from design §14; harness and testthat
green as root (container job) and non-root (runner job).

---

## Stage 5 — Hardening

Goal: the things a CRAN reviewer or a security-minded user will probe first.

- [ ] Label the PR `full-ci` and get every `native-checks` leg green: ASan
      containers, valgrind, gctorture at step 20, rchk, `-fanalyzer`, LTO,
      rcnst/rlibro/vnu. Forked children inherit the instrumentation; a child
      killed by SIGKILL skips LeakSanitizer's exit-time report, which is
      expected and not a finding.
- [ ] `workflow_dispatch` the `arch` workflow and get i386, musl and aarch64
      green: this is where the seccomp arch table, `sc_table.h` and the
      `__NR_*` fallbacks are proven.
- [x] Interrupt test: start `eval_safe(Sys.sleep(10))`, send SIGINT to the
      parent from a helper, assert the child is gone within a second.
- [x] Zombie audit: every exit path of `eval_safe()` and `run()` reaps the
      child (normal, timeout, interrupt, parent error between fork and wait).
- [x] fd-leak audit: in the child, after `lk_close_from`, `/proc/self/fd`
      lists exactly the expected set; a test opens a file outside the allowed
      hierarchy before `eval_safe()` and asserts the child cannot read from the
      inherited fd number.
- [x] Thread caveat: `confine()` errors in a multi-threaded session unless
      `force = TRUE`; test by setting `OPENBLAS_NUM_THREADS` or by starting a
      `parallel` cluster is unreliable, so test the `/proc/self/task` branch
      directly with a mocked count.
- [x] Review `apply_policy()` against §4 ordering with a checklist in the
      code comments: anything reordered must say why.
- [x] Run `/security-review` on the branch and the `critical-code-reviewer`
      skill on `src/`; fix what they find.
- [x] Check `R CMD check` wall time: examples under 5 s each, tests under
      60 s total.

Done differently: the security review ran as an independent read-only
reviewer over the C core, the adapter and the R engine; ten findings, all
fixed with regression tests, are recorded with the accepted residual risks in
`.agents/security.md`. Exit-path tests (interrupt as a real interrupt
condition, error in an output callback, grandchildren, `run()` timeout,
descriptor counts) are in `test-hardening.R`. Local suite: about 15 s.

Exit criteria: `native-checks` fully green under the `full` profile and
`arch` green on all three legs; interrupt, zombie and fd-leak tests in the
suite; security review findings closed or recorded in `.agents/` with a
reason.

---

## Stage 6 — Documentation

- [x] roxygen for every export: `@param`, `@return` (CRAN requires a
      `\value` section on every Rd, including the wrappers), `@examples`.
      One-way functions (`confine()`, `restrict_self()`, `seccomp_deny()`,
      `caps_drop_all()`, `no_new_privs()`, `setids()`, `chroot()`) show their
      example inside `eval_safe()` so it runs and is harmless, with a
      `\dontrun{}` block for the in-session form.
- [x] `landlock-package.R`: package-level page linking the three execution
      models and the layer table.
- [x] README: replace the template. Installation, a six-line `eval_safe()`
      example, the layers table with "works in containers / needs a VM"
      columns, a link to `status()`. Code blocks are static, not knitted
      (knitting on the Mac would show every layer skipped).
- [x] Vignettes (`Suggests: knitr, rmarkdown`; chunks `eval = FALSE` where
      they depend on the kernel, with pre-captured output shown):
      `getting-started` (policy, eval_safe, reading the report) and
      `layers` (what each layer stops, how it degrades, what Docker and
      Kubernetes typically allow: design §11).
- [x] `NEWS.md`: a real 0.1.0 entry listing the public API.
- [x] `_pkgdown.yml`: reference index grouped as Execution / Policy /
      Status / Confinement layers / Process, limits and ids (the `unix` API).
- [x] `getting-started` vignette opens with the migration from `unix`: what
      is identical (everything), what is new (`policy`, the report attribute,
      `status()`).
- [x] `inst/COPYRIGHTS`, `LICENSE.note` final wording.
- [x] `spelling::spell_check_package()` with a `inst/WORDLIST`.

Done differently: every output shown in the README and the vignettes was
captured on a GitHub Linux runner (kernel 6.17, Landlock ABI 7) by a
throwaway branch, never invented; the ABI 3 example uses the testing option
that caps the ABI, so its text is what the package prints on such a kernel.
Capturing found that the first drafts were wrong in three places (a `run()`
example blocked by the preset's seccomp filter, a report header showing the
kernel's ABI rather than the one used, `system()` warning rather than
failing). Vignettes are not evaluated at build time, since their output
depends on the kernel. Examples of irreversible functions run in
`eval_fork()`.

Exit criteria: `devtools::document()` produces no warnings, `R CMD check`
reports no undocumented objects or missing `\value`, pkgdown site builds in
CI and reads correctly.

---

## Stage 7 — CRAN readiness

- [ ] A `full-ci` run of `R-CMD-check` on the release candidate: macOS
      (Apple clang, arm64), ubuntu release and oldrel-1, the three containers
      (r-devel with gcc 16 and clang 23 at `-std=gnu23 -pedantic`). Target 0
      errors, 0 warnings, 0 notes other than "New submission".
- [ ] `native-checks` under `full` and a fresh `arch` dispatch, both green on
      the same commit. This replaces R-hub: every flavour on CRAN's
      "additional issues" page that applies to this package is covered by
      r-actions. win-builder is irrelevant (`OS_type: unix`).
- [x] `urlchecker::url_check()`; `tools::checkRd` via check;
      `goodpractice::gp()` as a hint source, not a gate.
- [x] Run the `/cran-extrachecks` and `/review-cran-submission` skills on
      the package and close every item they raise.
- [x] Compiled-code NOTE audit: `tools:::check_compiled_code` style scan for
      `exit`, `_exit`, `abort`, `printf`, `stdout`, `stderr` symbols in the
      built `.so`. With `raise(SIGKILL)` there should be none; if any remain,
      remove them rather than explain them.
- [x] DESCRIPTION final pass: Title in Title Case without the package name,
      Description without "This package", software names quoted, URL and
      BugReports present, `Authors@R` complete, `Date` absent (CRAN derives
      it), `Language: en-US`.
- [x] `cran-comments.md`: test environments, check results, "New submission",
      and one paragraph on why the package forks and why `OS_type: unix`.
      If `_exit` was kept after all, this is where it is justified with the
      `parallel` and `processx` precedent.
- [x] Reverse dependencies: none. Note it in cran-comments.

Done in Stage 7 rather than Stage 8: the version is bumped to 0.1.0
here, because `R CMD check --as-cran` with the incoming checks on gives a
NOTE for `0.0.0.9000` ("Version contains large components") and the exit
criterion is a clean check. The review skill found nothing else to fix: no
misspellings or bad URLs in the incoming check, every exported topic has
examples and a `\value`, the tarball holds no build artefacts, and the
shared library references no flagged symbols and only public R API entry
points. win-builder does not apply (`OS_type: unix`); R-hub is replaced by
the r-actions containers and the native ARM runner.

The architecture legs found five real problems before this point: a test
that assumed `getppid()` returns `-1` (i386 and musl return `-errno`),
Landlock tests left behind by the Stage 5 scratch-directory change, tests
reading `R.home()/COPYING` (absent on Alpine), a harness that used
`SYS_getpgrp` (absent on aarch64), and QEMU's inability to test seccomp,
which moved aarch64 to native `ubuntu-24.04-arm` runners.

Exit criteria: every check listed above is clean; cran-comments.md written;
a tag candidate commit on `main`.

---

## Stage 8 — Submission and release

- [ ] `usethis::use_release_issue(version = "0.1.0")` and work the generated
      checklist. (`Version: 0.1.0` and the NEWS heading were set in Stage 7.)
- [ ] `devtools::submit_cran()` or the web form at
      `https://cran.r-project.org/submit.html`; confirm the maintainer email
      within the hour it arrives.
- [ ] Review loop: a first submission is read by a human. Expected asks for a
      package like this one: a reference in Description, `\value` sections,
      `\dontrun` versus `\donttest`, examples that change the user's process.
      Reply by resubmitting with a "Resubmission" section in cran-comments
      that quotes each request and the change made.
- [ ] On acceptance: `git tag v0.1.0`, GitHub release with the NEWS entry,
      `usethis::use_dev_version()` → `0.1.0.9000`, pkgdown redeploys, add the
      CRAN badge to README. Add the package to R-universe
      (`pedrobtz.r-universe.dev`) so users get builds between CRAN releases.
- [ ] Open the 0.2.0 tracking issue: namespaces and mounts (M3), cgroup v2
      (M4), the `inst/apparmor` userns profile, then TOML/explain/trace (M5),
      and a data-only result mode (below).

### Considered for 0.2.0: a data-only result channel

`.agents/security.md` accepts one residual risk: under a policy the session
still `unserialize()`s bytes from a hostile child, and R's unserializer is
not hardened against crafted input. A result mode that transfers only atomic
vectors, lists and data frames in a restricted binary format, decoded without
R serialization, would close it. The maintainer's own `zubin` (typed binary
layouts) or `zujson` could carry it. Not in 0.1.0: neither is on CRAN yet, a
`LinkingTo` dependency would block the first submission, and the sandbox's
trusted base should stay small. `zufast`'s parsing primitives have no hot
path in this package.

Exit criteria: `landlock` 0.1.0 listed on CRAN with checks green on all
flavours; `main` is on `0.1.0.9000`.

---

## Parity with other sandboxes (after Stage 7, before submission)

A survey of the Rust, Go and Python Landlock bindings, libseccomp,
Docker's and Flatpak's seccomp rules, bubblewrap, nsjail, minijail,
firejail and systemd's sandboxing options listed what they offer and this
package lacked. Added, as far as the C core supports it with little glue:

- [x] New session for every child (`setsid`), as bwrap `--new-session`.
- [x] Die with the session (`PR_SET_PDEATHSIG`), as bwrap `--die-with-parent`,
      armed again after `setids`.
- [x] `run(wd, umask, clear_env, stdin)`; `grace` on `eval_safe()`,
      `eval_fork()` and `run()`.
- [x] seccomp argument rules: `block_tty`, `socket_families`,
      `lock_personality`; terminal ioctls blocked in the presets.
- [x] Named syscall groups and `seccomp_rules()` (the filter as a table,
      like libseccomp's `export_pfc`); `fs(missing = "ignore")`; further
      rlimits, `rtprio = 0` in every preset; a `umask()` verb;
      `deny_write_execute()` (PR_SET_MDWE); `partial` enforcement in the
      report; `status()` errata and `legacy_tiocsti`.
- [x] Documented: die-with-parent covers the child only; its own children
      are killed with its process group on a timeout or interrupt, but can
      outlive a session that dies.

Not added on purpose: `rlimit_*()` wrappers for the new resources.
`limits()` sets them in a policy, and further `rlimit_*` exports would go
beyond the `unix` API the package mirrors.

Deferred, with the reason:

- Landlock ABI 8–11 (TSYNC, pathname Unix sockets, UDP, NNP flag): the
  constants are in the kernel headers, but no CI kernel offers these ABIs
  yet (GitHub's runners report ABI 7), so the code could not be tested
  against a real kernel. Add when the runners' kernels do.
- seccomp allow-list mode: R's system call footprint varies with BLAS and
  packages; needs the M5 tracing tool to build a safe list.
- Library discovery for `run()` (`ldd`-style): runs or parses untrusted
  binaries; after M5.
- Securebits, `PR_SET_TSC`, CPU affinity: low value for confining R.
- Namespaces, private /tmp and network, cgroups, seccomp user
  notification: 0.2.0 (M3, M4).

## Standing rules while building

- Every commit installs and passes `R CMD check` on Linux; the C harness is
  part of CI, not a local-only tool.
- CI is the `pedrobtz/r-actions` set. A hand-written job is added only for
  what those workflows cannot express (today: the no-R harness). A failing
  leg is fixed in the package or, if the workflow is wrong, upstream in
  r-actions; it is never deleted from the caller to go green.
- The `unix` API is frozen at `unix` 1.6.0's formals. Anything new is a new
  function or a new trailing argument with a default, never a change to an
  existing signature.
- The core (`ll.c sc.c caps.c lim.c proc.c`) never includes R headers and
  never gains a package-specific assumption; design §15 wants it droppable
  into `unix/src/` unchanged.
- One-way operations are tested only in forked children. A test that
  restricts the check process is a bug even when it passes.
- When a kernel feature is unavailable the result is a report entry, never a
  silent no-op and never an error unless `strict = TRUE`.
- CRAN policy allows one update per one to two months after acceptance; batch
  fixes rather than resubmitting for each.
