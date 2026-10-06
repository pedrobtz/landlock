# Process information

Get or set attributes of the current process, with the same names,
arguments and results as the 'unix' package.

## Usage

``` r
getuid()

getgid()

geteuid()

getegid()

getpid()

getppid()

getpgid()

getpriority()

setuid(uid)

seteuid(uid)

setgid(gid)

setegid(gid)

setpgid(pgid = 0)

setpriority(prio)

kill(pid, signal = SIGTERM)
```

## Arguments

- uid:

  User id.

- gid:

  Group id.

- pgid:

  Process group id; `0` uses the current process id.

- prio:

  Priority.

- pid:

  Process id.

- signal:

  Signal number, [tools::SIGTERM](https://rdrr.io/r/tools/pskill.html)
  by default.

## Value

The getters and setters return the (new) value as an integer; `kill()`
returns `NULL`.

## Details

- `pid`: process id; `ppid`: parent process id; `pgid`: process group
  id.

- `uid`, `euid`: real and effective user id; `gid`, `egid`: group ids.

- `prio`: scheduling priority; a higher value is a lower priority.

An unprivileged process cannot change its `uid` and can only lower its
priority (raise the value).

## References

[GETUID(2)](https://man7.org/linux/man-pages/man2/getuid.2.html)
[GETPID(2)](https://man7.org/linux/man-pages/man2/getpid.2.html)
[GETPGID(2)](https://man7.org/linux/man-pages/man2/getpgid.2.html)
[GETPRIORITY(2)](https://man7.org/linux/man-pages/man2/getpriority.2.html)

## Examples

``` r
getuid()
#> [1] 1001
getpid()
#> [1] 6665
getpriority()
#> [1] 0
```
