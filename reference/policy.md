# Build a confinement policy

A policy is plain data: a list describing which layers to apply. The
builder verbs add to it and are meant to be piped. Nothing is enforced
until the policy is passed to
[`eval_safe()`](https://pedrobtz.github.io/landlock/reference/eval_safe.md),
[`run()`](https://pedrobtz.github.io/landlock/reference/run.md),
[`confine()`](https://pedrobtz.github.io/landlock/reference/apply_policy.md)
or
[`apply_policy()`](https://pedrobtz.github.io/landlock/reference/apply_policy.md).

## Usage

``` r
policy(best_effort = TRUE, log = NULL)

fs(
  p,
  read = NULL,
  write = NULL,
  exec = NULL,
  rw = NULL,
  tmp = FALSE,
  missing = c("error", "ignore")
)

net(p, bind = integer(), connect = integer())

scope(p, signal = TRUE, abstract_unix = TRUE)

limits(
  p,
  memory = NULL,
  cpu = NULL,
  fsize = NULL,
  nofile = NULL,
  pids = NULL,
  core = NULL,
  stack = NULL,
  data = NULL,
  memlock = NULL,
  rss = NULL,
  locks = NULL,
  sigpending = NULL,
  msgqueue = NULL,
  nice = NULL,
  rtprio = NULL,
  rttime = NULL
)

ids(p, uid = NULL, gid = NULL)

umask(p, mask)

deny_write_execute(p)

apparmor(p, profile)

syscalls(
  p,
  deny = character(),
  action = c("errno", "kill", "log", "trap"),
  errno = "EPERM",
  block_tty = FALSE,
  socket_families = NULL,
  lock_personality = FALSE
)

caps(p, keep = character())
```

## Arguments

- best_effort:

  If `TRUE` (the default), layers the kernel cannot provide are skipped
  and reported. If `FALSE`, applying the policy fails instead.

- log:

  Landlock audit logging (kernel ABI 7): `NULL` keeps the kernel
  default, `TRUE` also logs denials after an `exec()`, `FALSE` turns
  logging of denials off.

- p:

  A policy.

- read, write, exec, rw:

  Character vectors of paths.

- tmp:

  If `TRUE`, also allow reading and writing the call's own temporary
  directory: `tmp` of
  [`eval_safe()`](https://pedrobtz.github.io/landlock/reference/eval_safe.md),
  the child's `TMPDIR`. It is created for the call and, by default,
  removed afterwards. The session's
  [`tempdir()`](https://rdrr.io/r/base/tempfile.html) is deliberately
  not granted: the session may later trust what it finds there.

- missing:

  What to do, when the policy is applied, with a path that does not
  exist: `"error"` (the default) or `"ignore"` it, naming it in the
  report. Useful for policies shared between machines.

- bind, connect:

  Integer vectors of TCP ports that may be bound to or connected to.

- signal, abstract_unix:

  Logical: scope signals, abstract Unix sockets.

- memory, cpu, fsize, nofile, pids, core, stack, data, memlock:

  Resource ceilings; `NULL` leaves a resource alone.

- rss, locks, sigpending, msgqueue, nice, rtprio, rttime:

  Further resource limits (Linux): resident set size, file locks, queued
  signals, bytes in POSIX message queues, the nice ceiling (as
  `20 - value`), real-time priority (`0` forbids real-time scheduling)
  and real-time CPU time in microseconds. A limit the platform lacks is
  skipped and reported.

- uid, gid:

  User and group, as numeric ids or names.

- mask:

  File mode creation mask, as for
  [`Sys.umask()`](https://rdrr.io/r/base/files2.html), for example
  `"077"` so that every file the child creates is private.

- profile:

  Name of an AppArmor profile.

- deny:

  Character vector of system call names.

- action, errno:

  See
  [`seccomp_deny()`](https://pedrobtz.github.io/landlock/reference/seccomp_deny.md).

- block_tty:

  If `TRUE`, refuse the `ioctl()` requests that push input into a
  terminal or reprogram it (`TIOCSTI`, `TIOCLINUX`), as Flatpak does.

- socket_families:

  If not `NULL`, `socket()` may only create sockets of these families
  (any of `"unix"`, `"inet"`, `"inet6"`, `"netlink"`, `"packet"`,
  `"vsock"`); others fail with `EAFNOSUPPORT`. On i386 the C library
  creates sockets through `socketcall()`, which hides the family from
  the filter; `socketcall()` is then refused outright, so no socket of
  any family can be created there.

- lock_personality:

  If `TRUE`, `personality()` may only query or set the default execution
  domains, as in Docker's profile: no turning off address-space
  randomization.

- keep:

  Capability names to keep; see
  [`caps_keep()`](https://pedrobtz.github.io/landlock/reference/caps_drop_all.md).

## Value

An object of class `lk_policy`.

## Details

Layers and what they map to:

- `fs()`: Landlock filesystem rules. Calling it at all puts the whole
  filesystem under Landlock: everything not listed is denied. `read`
  allows reading files and listing directories, `write` allows creating,
  writing, renaming and removing (it does not imply `read`), `exec`
  allows executing (and reading, which the loader needs), `rw` is `read`
  plus `write`. Rules apply to the path and everything beneath it. Paths
  must exist when the policy is applied, not when it is built.

- `net()`: Landlock TCP rules (kernel ABI 4). Calling it restricts TCP
  `bind()` and `connect()` to the listed ports; `net()` alone blocks
  both. UDP and Unix sockets are not affected.

- `scope()`: Landlock scopes (ABI 6): no signals to, and no abstract
  Unix socket connections with, processes outside the sandbox.

- `limits()`: resource limits. Each is a ceiling: when the current hard
  limit is already lower it is kept. `memory` limits the address space
  (`RLIMIT_AS`), `pids` the number of processes for the user
  (`RLIMIT_NPROC`), `cpu` the CPU seconds, `fsize` the largest file,
  `nofile` the number of open files. Sizes accept numbers of bytes or
  strings such as `"512m"` or `"2g"`.

- `ids()`: switch to another user and group (root only). Applied after
  every other layer except the resource limits.

- `apparmor()`: change to an AppArmor profile, as
  `unix::eval_safe(profile =)` does.

- `syscalls()`: a seccomp filter denying the listed system calls; see
  [`seccomp_deny()`](https://pedrobtz.github.io/landlock/reference/seccomp_deny.md)
  for the actions and
  [`preset()`](https://pedrobtz.github.io/landlock/reference/preset.md)
  for ready-made sets. Calling `syscalls()` again adds to the list.

- `caps()`: drop every capability except `keep` and set `no_new_privs`;
  see
  [`caps_drop_all()`](https://pedrobtz.github.io/landlock/reference/caps_drop_all.md).

- `umask()`: the file mode creation mask of the child, so that files it
  creates get the intended permissions.

- `deny_write_execute()`: no memory mapping may become both writable and
  executable (Linux 6.3, `PR_SET_MDWE`), which stops code injected into
  writable memory from running. Breaks just-in-time compilers (V8,
  LLVM); no preset uses it.

## See also

[`preset()`](https://pedrobtz.github.io/landlock/reference/preset.md)
for ready-made policies,
[`status()`](https://pedrobtz.github.io/landlock/reference/status.md)
for what the kernel offers.

## Examples

``` r
p <- policy() |>
  fs(read = c(R.home(), .libPaths()), write = tempdir()) |>
  net() |>
  limits(memory = "2g", nofile = 256)
p
#> <landlock policy> best effort 
#>   fs read   /opt/R/4.6.1/lib/R, /home/runner/work/_temp/Library, /opt/R/4.6.1/lib/R/site-library, /opt/R/4.6.1/lib/R/library
#>   fs write  /tmp/RtmpgW0ZD4
#>   tcp       bind: none; connect: none
#>   limits    as=2 GiB, nofile=256 
```
