# Resource limits

Get and set process resource limits, with the same names, arguments and
results as the 'unix' package. Each function returns the current limits
and can optionally update them. `rlimit_all()` returns every limit.

## Usage

``` r
rlimit_all()

rlimit_as(cur = NULL, max = NULL)

rlimit_core(cur = NULL, max = NULL)

rlimit_cpu(cur = NULL, max = NULL)

rlimit_data(cur = NULL, max = NULL)

rlimit_fsize(cur = NULL, max = NULL)

rlimit_memlock(cur = NULL, max = NULL)

rlimit_nofile(cur = NULL, max = NULL)

rlimit_nproc(cur = NULL, max = NULL)

rlimit_stack(cur = NULL, max = NULL)
```

## Arguments

- cur:

  New soft limit, or `NULL` to keep it. `Inf` means unlimited.

- max:

  New hard limit, or `NULL` to keep it.

## Value

A list with elements `cur` and `max`; `Inf` means unlimited.
`rlimit_all()` returns a list of two named numeric vectors, `cur` and
`max`.

## Details

Each resource has a soft limit (`cur`), which the kernel enforces, and a
hard limit (`max`), the ceiling for the soft limit. An unprivileged
process may set its soft limit anywhere up to the hard limit and may
lower its hard limit, irreversibly. Setting `cur` above the current
`max` also tries to raise `max`, which only a privileged process may do.

- `as`: the maximum size of the virtual address space, in bytes.

- `core`: the maximum size of a core dump.

- `cpu`: CPU time in seconds; the process receives `SIGXCPU` at the soft
  limit.

- `data`: the maximum size of the data segment.

- `fsize`: the largest file the process may create.

- `memlock`: bytes of memory that may be locked into RAM.

- `nofile`: one more than the largest file descriptor number.

- `nproc`: processes for the real user id; not enforced for root.

- `stack`: the maximum stack size.

## References

[GETRLIMIT(2)](https://man7.org/linux/man-pages/man2/setrlimit.2.html)

## Examples

``` r
rlimit_all()
#> $cur
#>       as     core      cpu     data    fsize  memlock   nofile    nproc 
#>      Inf        0      Inf      Inf      Inf  8388608    65536    63791 
#>    stack 
#> 16777216 
#> 
#> $max
#>      as    core     cpu    data   fsize memlock  nofile   nproc   stack 
#>     Inf     Inf     Inf     Inf     Inf 8388608   65536   63791     Inf 
#> 
rlimit_nofile()
#> $cur
#> [1] 65536
#> 
#> $max
#> [1] 65536
#> 
```
