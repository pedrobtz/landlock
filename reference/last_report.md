# The report of the last enforcement

Every
[`eval_safe()`](https://pedrobtz.github.io/landlock/reference/eval_safe.md),
[`run()`](https://pedrobtz.github.io/landlock/reference/run.md),
[`confine()`](https://pedrobtz.github.io/landlock/reference/apply_policy.md)
and
[`apply_policy()`](https://pedrobtz.github.io/landlock/reference/apply_policy.md)
call that was given a policy records which layers it applied and which
it skipped.

## Usage

``` r
last_report()
```

## Value

The most recent report (class `lk_report`), or `NULL` if no policy has
been applied in this session.
