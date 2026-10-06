## New submission

landlock evaluates R expressions, or runs programs, in a forked child process
that the Linux kernel confines (Landlock filesystem and TCP rules, a
seccomp-bpf system call filter, capability dropping, resource limits). It is
also a drop-in replacement for the 'unix' package: it exports every function
of 'unix' 1.6.0 with the same arguments.

## Notes for the reviewer

* `OS_type: unix`. The package forks the R session, as `parallel::mcparallel()`
  and 'unix' do. On macOS the confinement layers are reported as unavailable
  and everything else works; Windows has no fork.

* No R internals. Unlike 'unix', the package does not write to `R_TempDir`,
  `R_Interactive` or the console pointers. The forked child never returns to
  the R toplevel: it runs under `R_UnwindProtect()` and ends with
  `raise(SIGKILL)` (as 'unix' does), so compiled code calls no `exit()`,
  `_exit()` or `abort()` and writes nothing to stdout or stderr.

* Examples and tests never restrict the R process running them. Every
  irreversible function (`confine()`, `restrict_self()`, `seccomp_deny()`,
  `caps_drop_all()`, `setids()`, `chroot()`) is demonstrated inside
  `eval_fork()`, a short-lived child. Root-only examples are guarded by
  `if (getuid() == 0)`.

* The vignettes show code with output captured on Linux rather than
  evaluating it, because the output depends on the kernel of the machine
  that builds them.

* `src/compat/` contains constants and structure layouts from the Linux
  user-space API headers (GPL-2.0 WITH Linux-syscall-note, which permits use
  from user space). Two test files are adapted from 'unix' (MIT). Both are
  described in `inst/COPYRIGHTS`; Jeroen Ooms is listed as copyright holder
  for the adapted tests.

## Test environments

* GitHub Actions: macOS (R release), Ubuntu 24.04 x86_64 (R release and
  oldrel-1), Ubuntu 24.04 aarch64 (R release, native ARM runner).
* R-hub containers with CRAN's r-devel compilers: clang 23 (`-std=gnu23
  -pedantic`), Ubuntu clang, GCC 16.
* Additional checks: AddressSanitizer and UBSan (gcc and clang), valgrind,
  gctorture, rchk, LTO, `-fanalyzer`, rcnst, rlibro, vnu, and 32-bit (i386)
  and musl (Alpine) builds.

## R CMD check results

0 errors | 0 warnings | 1 note

* This is a new release.

## Reverse dependencies

None: this is a new package.
