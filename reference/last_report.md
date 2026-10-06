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

## Examples

``` r
eval_safe(sum(1:10), policy = preset("numeric"))
#> [1] 55
last_report()
#> <landlock report> Landlock ABI 7 
#>   landlock-fs     applied  ABI 7, 15 rules
#>   landlock-net    applied  TCP bind: none; connect: none
#>   landlock-scope  applied  signal, abstract_unix
#>   seccomp         applied  deny 76 calls (errno EPERM); terminal injection ioctls refused; not on this architecture: socketcall; clone() with namespace flags refused
#>   caps            applied  bounding set kept (needs CAP_SETPCAP); effective, permitted, inheritable and ambient cleared
#>   limits          applied  rtprio=0
```
