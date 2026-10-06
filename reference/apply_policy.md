# Apply a policy

`apply_policy()` is the engine behind
[`eval_safe()`](https://pedrobtz.github.io/landlock/reference/eval_safe.md),
[`run()`](https://pedrobtz.github.io/landlock/reference/run.md) and
`confine()`: it applies the layers of a
[`policy()`](https://pedrobtz.github.io/landlock/reference/policy.md) to
the calling process, in the order of design.md section 4 (AppArmor,
Landlock, user and group ids, resource limits). It is irreversible; call
it in a child process, or use `confine()`, which adds a check for
threads.

## Usage

``` r
apply_policy(p, strict = !isTRUE(p$best_effort))

confine(p, force = FALSE, strict = !isTRUE(p$best_effort))
```

## Arguments

- p:

  A
  [`policy()`](https://pedrobtz.github.io/landlock/reference/policy.md).

- strict:

  If `TRUE`, fail when the kernel cannot provide a requested layer
  instead of skipping it. Defaults to the policy's `best_effort`
  setting.

- force:

  Apply even if the session has more than one thread.

## Value

A report of class `lk_report`: a data frame with one row per requested
layer and the columns `layer`, `status` (`"applied"` or `"skipped"`) and
`detail`. Returned invisibly; also available as
[`last_report()`](https://pedrobtz.github.io/landlock/reference/last_report.md).

## Details

`confine()` applies a policy to the current R session. Landlock
restricts only the calling thread and the threads and processes it
creates later, so `confine()` refuses to run in a session that already
has other threads (a multi-threaded BLAS, for example) unless
`force = TRUE`.
