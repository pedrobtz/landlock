# Restrict this process with Landlock

A thin wrapper over the kernel's Landlock interface for the calling
process: the filesystem is denied except for the listed paths, TCP is
restricted when `tcp_bind` or `tcp_connect` is given, and the scopes are
applied. Irreversible. Landlock restricts the calling thread and what it
creates afterwards, not threads that already exist; see
[`confine()`](https://pedrobtz.github.io/landlock/reference/apply_policy.md).

## Usage

``` r
restrict_self(
  read = NULL,
  write = NULL,
  exec = NULL,
  tcp_bind = NULL,
  tcp_connect = NULL,
  scope = c("signal", "abstract_unix"),
  best_effort = TRUE,
  log = NULL
)
```

## Arguments

- read, write, exec:

  Character vectors of paths; see
  [`fs()`](https://pedrobtz.github.io/landlock/reference/policy.md).

- tcp_bind, tcp_connect:

  Integer vectors of TCP ports, or `NULL` to leave TCP alone.

- scope:

  Scopes to apply: any of `"signal"` and `"abstract_unix"`.

- best_effort, log:

  See
  [`policy()`](https://pedrobtz.github.io/landlock/reference/policy.md).

## Value

The report, invisibly; see
[`apply_policy()`](https://pedrobtz.github.io/landlock/reference/apply_policy.md).

## Examples

``` r
# Irreversible, so shown in a throwaway child. Where Landlock is
# available, everything outside R's own files becomes unreadable.
eval_fork({
  restrict_self(read = c(R.home(), .libPaths()))
  tryCatch(readLines("/etc/passwd", n = 1), warning = conditionMessage)
})
#> [1] "cannot open file '/etc/passwd': Permission denied"
```
