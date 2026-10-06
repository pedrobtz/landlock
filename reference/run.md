# Run a program in a confined child process

Forks, applies `policy` in the child, closes every inherited file
descriptor except the standard streams, and executes `cmd` (looked up in
`PATH`). Standard input is `/dev/null`.

## Usage

``` r
run(
  cmd,
  args = character(),
  policy = NULL,
  timeout = 0,
  std_out = TRUE,
  std_err = TRUE,
  env = NULL
)
```

## Arguments

- cmd:

  Program to run.

- args:

  Character vector of arguments.

- policy:

  A
  [`policy()`](https://pedrobtz.github.io/landlock/reference/policy.md),
  or `NULL` for none. Under a Landlock filesystem policy the program
  needs `exec` permission on itself and on the dynamic loader
  (`ld-linux*.so`, under `/lib`, `/lib64` or `/usr/lib`), which the
  kernel opens for execution as well, and `read` permission on its
  shared libraries; see
  [`preset()`](https://pedrobtz.github.io/landlock/reference/preset.md).

- timeout:

  Wall-clock limit in seconds; `0` for none.

- std_out, std_err:

  `TRUE` to capture the output in the result, `FALSE` or `NULL` to
  discard it, or a file name, connection or function as in
  [`eval_safe()`](https://pedrobtz.github.io/landlock/reference/eval_safe.md).

- env:

  Named character vector of environment variables to set for the
  program.

## Value

A list with `status` (exit status, `NA` if the program was killed by a
signal), `signal` (the signal, or `NA`), and `stdout` and `stderr` (raw
vectors when captured, else `NULL`). The report of the applied policy is
available as
[`last_report()`](https://pedrobtz.github.io/landlock/reference/last_report.md).

## Examples

``` r
res <- run("echo", "hello")
rawToChar(res$stdout)
#> [1] "hello\n"
```
