# Evaluate in a forked, optionally confined, child process

`eval_fork()` evaluates an expression in a temporary fork of the R
session and returns its value, without side effects on the session.
`eval_safe()` adds error handling, graphics isolation, resource limits,
user switching, an AppArmor profile and, through `policy`, every layer
of a
[`policy()`](https://pedrobtz.github.io/landlock/reference/policy.md).
Both keep the arguments of the 'unix' package functions of the same
name, in the same order; `policy` is added at the end.

## Usage

``` r
eval_safe(
  expr,
  tmp = tempfile("fork"),
  std_out = stdout(),
  std_err = stderr(),
  timeout = 0,
  priority = NULL,
  uid = NULL,
  gid = NULL,
  rlimits = NULL,
  profile = NULL,
  device = pdf,
  policy = NULL
)

eval_fork(
  expr,
  tmp = tempfile("fork"),
  std_out = stdout(),
  std_err = stderr(),
  timeout = 0
)
```

## Arguments

- expr:

  Expression to evaluate.

- tmp:

  Temporary directory for the child; becomes its `TMPDIR`.

- std_out, std_err:

  Where the child's output goes; see *Output streams*.

- timeout:

  Wall-clock limit in seconds; `0` for none.

- priority:

  Scheduling priority of the child; see
  [`setpriority()`](https://pedrobtz.github.io/landlock/reference/process.md).

- uid, gid:

  User and group to switch to (root only), as ids or names. After the
  switch the child can only read what that user can read, including the
  R libraries it lazy-loads code from: landlock's own functions are
  loaded beforehand, but functions of other packages used for the first
  time in the child must be readable by that user.

- rlimits:

  Named vector or list of resource limits, as in 'unix', for example
  `c(cpu = 60, fsize = 1e6)`. Each sets both the soft and the hard
  limit; zero and `NA` are ignored.

- profile:

  AppArmor profile for the child.

- device:

  Graphics device to use in the child.

- policy:

  A
  [`policy()`](https://pedrobtz.github.io/landlock/reference/policy.md)
  applied in the child before `expr` runs. When given, the child also
  closes every file descriptor it inherited except its standard streams,
  because Landlock does not revoke files that are already open.

## Value

The value of `expr`, visible or invisible as in the child. The report of
the applied policy is available as
[`last_report()`](https://pedrobtz.github.io/landlock/reference/last_report.md).

## Details

The child is killed when `timeout` seconds of wall-clock time pass, or
when the session is interrupted. Errors in the child are raised again in
the session with their original class. Output the child writes is
forwarded as it arrives.

Some software is not fork-safe and cannot be used in the child once the
session has loaded it (Java, and on macOS anything built on
CoreFoundation, including a `libcurl` built against SecureTransport).
The same holds for
[`parallel::mcparallel()`](https://rdrr.io/r/parallel/mcparallel.html).

## Output streams

`std_out` and `std_err` may be `TRUE` (the session's
[`stdout()`](https://rdrr.io/r/base/showConnections.html) and
[`stderr()`](https://rdrr.io/r/base/showConnections.html)), `FALSE` or
`NULL` (discard), a file name, a connection, or a function of one
argument that receives each chunk as a raw vector.

## Differences from 'unix'

The 'unix' package switches
[`tempdir()`](https://rdrr.io/r/base/tempfile.html) and
[`interactive()`](https://rdrr.io/r/base/interactive.html) inside the
child by writing to R internals, which a package on CRAN may not do.
Here `tmp` becomes the child's `TMPDIR` (seen by
[`Sys.getenv()`](https://rdrr.io/r/base/Sys.getenv.html), child
processes and C libraries) while
[`tempdir()`](https://rdrr.io/r/base/tempfile.html) keeps the session's
value, and [`interactive()`](https://rdrr.io/r/base/interactive.html)
keeps the session's value; standard input is `/dev/null`. Output is
captured with [`sink()`](https://rdrr.io/r/base/sink.html), which also
works under front-ends such as RStudio.

## Examples

``` r
eval_safe(rnorm(5))
#> [1] -1.400043517  0.255317055 -2.437263611 -0.005571287  0.621552721

# errors keep their class
tryCatch(eval_safe(stop("oh no")), error = function(e) conditionMessage(e))
#> [1] "oh no"

# a wall-clock limit, enforced even inside C code
try(eval_safe(Sys.sleep(10), timeout = 1))
#> Error : timeout reached (1 sec)
```
