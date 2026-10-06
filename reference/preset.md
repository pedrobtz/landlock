# Ready-made policies

Policies for common cases, built for the running session when called
(they read [`R.home()`](https://rdrr.io/r/base/Rhome.html),
[`.libPaths()`](https://rdrr.io/r/base/libPaths.html) and
[`tempdir()`](https://rdrr.io/r/base/tempfile.html)). Start from one and
add to it with the
[`policy()`](https://pedrobtz.github.io/landlock/reference/policy.md)
verbs.

## Usage

``` r
preset(name, ...)
```

## Arguments

- name:

  Name of the preset.

- ...:

  Arguments of the preset: `lib` for `"install"` (default the first
  library path), `port` for `"plumber"` (default 8000).

## Value

A [`policy()`](https://pedrobtz.github.io/landlock/reference/policy.md),
or for a system call set a character vector.

## Details

Policies:

- `"numeric"`: evaluate R code that only computes. Reads R, the
  installed packages and system libraries; reads and writes only the
  session's temporary directory; may execute nothing; no TCP; signals
  and abstract sockets scoped to the sandbox; the `"dangerous"`,
  `"no_exec"` and `"no_net"` system calls denied; all capabilities
  dropped.

- `"install"`: install a package from source. As `"numeric"`, plus
  executing the compiler toolchain (and the dynamic loader, which the
  kernel opens for execution too) and writing to `lib`; only the
  `"dangerous"` calls are denied.

- `"plumber"`: serve HTTP. As `"numeric"`, plus binding to `port`; the
  `"dangerous"` and `"no_exec"` calls are denied.

System call sets, character vectors for
[`syscalls()`](https://pedrobtz.github.io/landlock/reference/policy.md)
and
[`seccomp_deny()`](https://pedrobtz.github.io/landlock/reference/seccomp_deny.md):

- `"dangerous"`: calls a sandboxed R process has no use for and that
  widen the kernel's attack surface or escape a sandbox: `ptrace`,
  `process_vm_readv`, mounting, namespaces, keyrings, `bpf`,
  `perf_event_open`, `io_uring`, `userfaultfd`, kernel modules, `kexec`,
  `reboot`, swap, clock setting, `open_by_handle_at`, NUMA policy calls,
  and `landlock_*` and `seccomp` themselves (the sandbox is complete by
  the time the filter is installed). Never `set*id` or `capset`, which
  the later steps of
  [`apply_policy()`](https://pedrobtz.github.io/landlock/reference/apply_policy.md)
  use.

- `"no_exec"`: `execve` and `execveat`
  ([`system()`](https://rdrr.io/r/base/system.html) stops working).

- `"no_net"`: socket creation and use. Also stops DNS, and is the only
  way to stop UDP without a network namespace.

Paths that do not exist on this system are left out of the policies.

## Examples

``` r
preset("numeric")
#> <landlock policy> best effort 
#>   fs read   /opt/R/4.6.1/lib/R, /home/runner/work/_temp/Library, /opt/R/4.6.1/lib/R/site-library, /opt/R/4.6.1/lib/R/library, /usr, /lib, /lib64, /opt/R, /etc/ld.so.cache, /etc/localtime, /etc/timezone, /etc/os-release, /dev/urandom, /dev/null, /tmp/RtmpaSV0p3, /dev/null
#>   fs write  /tmp/RtmpaSV0p3, /dev/null
#>   tcp       bind: none; connect: none
#>   scope     signal, abstract_unix  
#>   syscalls  deny 72 calls, action errno 
#>   caps      keep none 
```
