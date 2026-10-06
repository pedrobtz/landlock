# Worked examples

This article runs every example when the site is built. The machine that
built it:

``` r

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

On a kernel without Landlock, or on macOS, the same code runs; the
layers the kernel lacks are reported as skipped instead of enforced.

## Evaluate code you do not trust

A common case: an application receives R code, from a web form or an
API, and has to run it.
[`eval_safe()`](https://pedrobtz.github.io/landlock/reference/eval_safe.md)
runs it in a forked child, and a policy decides what that child may do.
The `"numeric"` preset allows computing and nothing else.

``` r

run_untrusted <- function(code, timeout = 5) {
  expr <- str2lang(code)
  eval_safe(eval(expr), policy = preset("numeric") |> limits(memory = "4g"),
            timeout = timeout)
}
```

Ordinary computation works:

``` r

run_untrusted("summary(lm(mpg ~ wt + hp, data = mtcars))$r.squared")
#> [1] 0.8267855
```

Reading a file outside R’s own files fails. Landlock refuses the open,
which R reports as a warning (the reason) and an error:

``` r

run_untrusted("readLines('/etc/passwd', n = 1)")
#> Error in `file()`:
#> ! cannot open the connection
```

Warnings raised in the child stay in the child, as with
`unix::eval_safe()`. Catch them inside the expression to see the reason:

``` r

run_untrusted("tryCatch(readLines('/etc/passwd', n = 1), warning = conditionMessage)")
#> [1] "cannot open file '/etc/passwd': Permission denied"
```

Starting a program fails: the preset’s seccomp filter refuses `execve`.

``` r

run_untrusted("tryCatch(system('id', intern = TRUE), error = conditionMessage, warning = conditionMessage)")
#> [1] "cannot popen 'id', probable reason 'Operation not permitted'"
```

So does opening a socket, which the filter refuses as well:

``` r

run_untrusted("tryCatch(serverSocket(18080), error = conditionMessage)")
#> [1] "creation of server socket failed: port 18080 cannot be opened"
```

A loop that never ends is killed when the timeout passes, even when it
is stuck in C code:

``` r

run_untrusted("repeat {}", timeout = 2)
#> Error:
#> ! timeout reached (2 sec)
```

And a request for more memory than the limit fails inside the child,
leaving the session untouched:

``` r

run_untrusted("x <- numeric(1e9)")
#> Error:
#> ! cannot allocate vector of size 7.5 Gb
```

What was enforced is in the report:

``` r

last_report()
#> <landlock report> Landlock ABI 7 
#>   landlock-fs     applied  ABI 7, 15 rules
#>   landlock-net    applied  TCP bind: none; connect: none
#>   landlock-scope  applied  signal, abstract_unix
#>   seccomp         applied  deny 76 calls (errno EPERM); terminal injection ioctls refused; not on this architecture: socketcall; clone() with namespace flags refused
#>   caps            applied  bounding set kept (needs CAP_SETPCAP); effective, permitted, inheritable and ambient cleared
#>   limits          applied  rtprio=0, as=4294967296
```

A layer the kernel cannot provide is reported as `skipped`. When that is
not acceptable, build the policy with `policy(best_effort = FALSE)` and
the evaluation fails instead of running with less protection.

## A policy for a task

Presets are a starting point. For a specific job, list exactly what it
needs. Here a function summarizes a CSV file from an input directory and
writes the result to an output directory; it may read the input, write
the output, and nothing else of the user’s.

``` r

input <- file.path(tempdir(), "input")
output <- file.path(tempdir(), "output")
dir.create(input)
dir.create(output)
write.csv(mtcars, file.path(input, "cars.csv"), row.names = FALSE)

task_policy <- policy() |>
  fs(read = c(R.home(), .libPaths(), "/usr", input), write = output) |>
  net() |>
  syscalls(deny = c(preset("dangerous"), preset("no_exec"), preset("no_net"))) |>
  caps() |>
  limits(memory = "4g", cpu = 30)
task_policy
#> <landlock policy> best effort 
#>   fs read   /opt/R/4.6.1/lib/R, /home/runner/work/_temp/Library, /opt/R/4.6.1/lib/R/site-library, /opt/R/4.6.1/lib/R/library, /usr, /tmp/RtmpFrQMag/input
#>   fs write  /tmp/RtmpFrQMag/output
#>   tcp       bind: none; connect: none
#>   limits    as=4 GiB, cpu=30 
#>   syscalls  deny 77 calls, action errno 
#>   caps      keep none
```

``` r

summarise_file <- function(name) {
  eval_safe({
    d <- read.csv(file.path(input, name))
    s <- aggregate(mpg ~ cyl, data = d, FUN = mean)
    write.csv(s, file.path(output, "summary.csv"), row.names = FALSE)
    nrow(s)
  }, policy = task_policy)
}

summarise_file("cars.csv")
#> [1] 3
read.csv(file.path(output, "summary.csv"))
#>   cyl      mpg
#> 1   4 26.66364
#> 2   6 19.74286
#> 3   8 15.10000
```

The same code cannot reach anything else. Writing into the input
directory, or reading the output it just wrote, is refused: `write` and
`read` are separate rights.

``` r

eval_safe(file.create(file.path(input, "planted.csv")), policy = task_policy)
#> [1] FALSE
eval_safe(file.exists(file.path(output, "summary.csv")), policy = task_policy)
#> [1] TRUE
eval_safe(tryCatch(readLines(file.path(output, "summary.csv")), warning = conditionMessage),
          policy = task_policy)
#> [1] "cannot open file '/tmp/RtmpFrQMag/output/summary.csv': Permission denied"
```

[`file.exists()`](https://rdrr.io/r/base/files.html) still answers:
Landlock governs opening files, not looking at their metadata.

## Running a program

[`run()`](https://pedrobtz.github.io/landlock/reference/run.md) applies
a policy to a program instead of R code. The program needs permission to
execute itself and the dynamic loader (the kernel opens both for
execution), and to read its libraries.

``` r

words <- file.path(input, "words.txt")
writeLines(c("pear", "apple", "fig"), words)

sort_policy <- policy() |>
  fs(read = c("/usr", "/etc/ld.so.cache", words), exec = c("/usr/bin", "/usr/lib")) |>
  net()

res <- run("sort", words, policy = sort_policy)
res$status
#> [1] 0
cat(rawToChar(res$stdout))
#> apple
#> fig
#> pear
```

The same program on a file the policy does not list:

``` r

res <- run("sort", "/etc/passwd", policy = sort_policy)
res$status
#> [1] 2
cat(rawToChar(res$stderr))
#> sort: open failed: /etc/passwd: Permission denied
```

### Working directory, environment and input

[`run()`](https://pedrobtz.github.io/landlock/reference/run.md) sets up
the program’s working directory, environment and standard input the way
a shell would, before the policy applies. The input file does not need
to be in the policy: it is opened first, like a redirection.

``` r

secret <- file.path(output, "input.txt")
writeLines(c("two", "one"), secret)
res <- run("sort", policy = sort_policy, stdin = secret, wd = input,
           clear_env = TRUE, env = c(LC_ALL = "C"))
cat(rawToChar(res$stdout))
#> one
#> two
```

A program that needs time to clean up can be given a grace period
between `SIGTERM` and `SIGKILL` when the timeout passes. Its output is
streamed to the console here (`std_out = ""`), since a call that times
out returns no result:

``` r

run("sh", c("-c", "trap 'echo cleaning up; exit 0' TERM; sleep 60 & wait"),
    timeout = 1, grace = 2, std_out = "")
#> cleaning up
#> Error:
#> ! timeout reached (1 sec)
```

## Coming from unix

Code written for the ‘unix’ package runs unchanged:

``` r

eval_safe(rlimit_cpu()$cur, rlimits = c(cpu = 10))
#> [1] 10
eval_fork(getppid() == getpid())
#> [1] FALSE
```

and gains confinement by adding `policy`:

``` r

eval_safe(sum(1:10), rlimits = c(cpu = 10), policy = preset("numeric"))
#> [1] 55
```

## Values from confined code

Under a policy the package never evaluates what the child sends back,
but the value you receive is the child’s data. R values can carry code:
closures, and environments whose active bindings run when read. From
code you do not trust, return plain data such as vectors, lists and data
frames, as `run_untrusted()` above does.
