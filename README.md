
<!-- README.md is written by hand, not knitted: the output below needs a
     Linux kernel with Landlock, which the machine building the site may lack. -->

# landlock

<!-- badges: start -->
[![R-CMD-check](https://github.com/pedrobtz/landlock/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/pedrobtz/landlock/actions/workflows/R-CMD-check.yaml)
[![native-checks](https://github.com/pedrobtz/landlock/actions/workflows/native-checks.yaml/badge.svg)](https://github.com/pedrobtz/landlock/actions/workflows/native-checks.yaml)
[![coverage](https://raw.githubusercontent.com/pedrobtz/landlock/main/.github/badges/coverage.svg)](https://github.com/pedrobtz/landlock/actions/workflows/coverage.yaml)
<!-- badges: end -->

landlock evaluates R expressions, or runs programs, in a child process that
the Linux kernel confines: which files it may read, write and execute, which
TCP ports it may use, which system calls it may make, which capabilities and
resource limits it keeps. It needs no external libraries and no root.

It is also a drop-in replacement for the
[unix](https://cran.r-project.org/package=unix) package: every function
`unix` exports exists here with the same name and arguments, so replacing
`library(unix)` with `library(landlock)` changes nothing until you pass a
policy.

## Installation

```r
# install.packages("pak")
pak::pak("pedrobtz/landlock")
```

## Example

Evaluate untrusted code with the `"numeric"` preset: it may read R and its
packages, read and write the session's temporary directory, and nothing
else. No programs, no network, no dangerous system calls.

```r
library(landlock)

eval_safe(coef(lm(mpg ~ wt, data = mtcars)), policy = preset("numeric"))
#> (Intercept)          wt 
#>   37.285126   -5.344472 

eval_safe(tryCatch(readLines("/etc/passwd"), warning = conditionMessage),
          policy = preset("numeric"))
#> [1] "cannot open file '/etc/passwd': Permission denied"

run("id", policy = preset("numeric"))
#> Error: cannot run 'id': Operation not permitted
```

What was applied, and what the kernel could not provide, is in the report:

```r
last_report()
#> <landlock report> Landlock ABI 7 
#>   landlock-fs     applied  ABI 7, 14 rules
#>   landlock-net    applied  TCP bind: none; connect: none
#>   landlock-scope  applied  signal, abstract_unix
#>   seccomp         applied  deny 76 calls (errno EPERM); terminal injection ioctls refused; not on this architecture: socketcall; clone() with namespace flags refused
#>   caps            applied  bounding set kept (needs CAP_SETPCAP); effective, permitted, inheritable and ambient cleared
#>   limits          applied  rtprio=0
```

Policies are plain data and compose:

```r
p <- policy() |>
  fs(read = c(R.home(), .libPaths()), tmp = TRUE) |>
  net(connect = 443) |>
  syscalls(deny = preset("dangerous")) |>
  limits(memory = "2g", cpu = 60, nofile = 256)

eval_safe(my_analysis(), policy = p, timeout = 30)
run("pandoc", c("in.md", "-o", "out.html"), policy = p)
```

## Layers

| Layer | Stops | Needs | In Docker / Kubernetes |
|---|---|---|---|
| `fs()` (Landlock) | reading, writing, executing outside listed paths | Linux 5.13 | yes |
| `net()` (Landlock) | TCP bind and connect outside listed ports | Linux 6.7 | yes |
| `scope()` (Landlock) | signals and abstract sockets beyond the sandbox | Linux 6.12 | yes |
| `syscalls()` (seccomp) | the listed system calls; terminal-injection `ioctl`s; other socket families; `personality()` changes | Linux 3.5 | yes |
| `caps()` | capabilities, and regaining them | Linux | yes |
| `limits()` | memory, CPU time, file size, open files, processes, real-time scheduling | any Unix | yes |
| `deny_write_execute()` | memory that is both writable and executable | Linux 6.3 | yes |
| `ids()` | running as the current user (root only) | any Unix | yes |
| `apparmor()` | what the AppArmor profile forbids | AppArmor | host-dependent |

A layer the kernel cannot provide is skipped and reported, never silently
ignored, and one it can only partly provide is reported as `partial`;
`policy(best_effort = FALSE)` turns either into an error. Every child also
runs in a session of its own, without a controlling terminal, and dies with
the R session. `status()`
shows what the running kernel offers:

```r
status()
#> <landlock status> Linux 6.17.0-1022-azure 
#>   Landlock       ABI 7 
#>   seccomp        none 
#>   no_new_privs   no 
#>   capabilities   none effective 
#>   user ns        yes 
#>   cgroup         v2 
#>   TIOCSTI        restricted 
#>   AppArmor       enabled, profile unconfined 
```

Off Linux, `eval_safe()`, `run()`, resource limits and the whole `unix` API
work; the confinement layers report themselves as skipped.

## Learn more

* `vignette("landlock")`: getting started, and moving from `unix`.
* `vignette("layers")`: what each layer does and how it degrades.
