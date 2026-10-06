# System call filters

`seccomp_deny()` installs a seccomp-bpf filter on the calling process
that makes the listed system calls fail (or kills the process) and
allows every other call. Filters stack and cannot be removed; it also
sets `no_new_privs`. Calls made for another architecture's ABI (32-bit
calls on a 64-bit kernel) are always refused. Linux only.

## Usage

``` r
seccomp_deny(
  syscalls,
  action = c("errno", "kill", "log", "trap"),
  errno = "EPERM"
)

seccomp_status()

syscall_table()
```

## Arguments

- syscalls:

  Character vector of system call names. Names that exist only on other
  architectures are ignored.

- action:

  What happens on a denied call; see Details.

- errno:

  Error returned by `action = "errno"`: a name such as `"EPERM"` or
  `"EACCES"`, or a number.

## Value

`seccomp_deny()`: `TRUE` if every thread got the filter, `FALSE` if only
the calling one, invisibly. `seccomp_status()`: a list with the `mode`
(0 none, 1 strict, 2 filter) and the number of `filters`.
`syscall_table()`: a data frame with `name` and `nr`.

## Details

The filter goes to every thread of the process when the kernel can do
that (seccomp's TSYNC flag), otherwise only to the calling thread.

Two calls get special treatment. `clone3` always fails with `ENOSYS`, so
the C library falls back to `clone()`, whose flags a filter can inspect.
Denying `unshare` also refuses `clone()` with any namespace flag, which
would otherwise create the same namespaces.

Actions: `"errno"` makes the call fail with `errno` (default `EPERM`),
`"kill"` kills the process with `SIGSYS`, `"log"` allows the call but
logs it to the kernel audit log, `"trap"` sends `SIGSYS` to the thread.

`syscall_table()` lists the system calls this build knows for this
architecture;
[`preset()`](https://pedrobtz.github.io/landlock/reference/preset.md)
provides the sets `"dangerous"`, `"no_exec"` and `"no_net"`.
`seccomp_status()` reports the filter state of this process.
