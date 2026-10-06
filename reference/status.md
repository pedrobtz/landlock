# What this kernel offers

Probes the running system for every confinement layer the package can
use. Nothing is changed: the user-namespace probe runs in a short-lived
forked child.

## Usage

``` r
status()
```

## Value

A list of class `lk_status` with elements:

- os, kernel:

  Operating system and kernel release.

- landlock_abi:

  Landlock ABI version; 0 when Landlock is not available (older kernel,
  not built, or disabled at boot).

- landlock_errata:

  Bitmask of Landlock fixes the kernel reports (Linux 6.15 and later),
  `NA` where the kernel cannot say.

- seccomp, seccomp_filters:

  Seccomp mode of this process (0 none, 1 strict, 2 filter) and the
  number of filters installed.

- no_new_privs:

  Whether `no_new_privs` is already set.

- caps:

  Capability sets of this process as hexadecimal strings.

- userns:

  User namespace limits and whether a child can create one.

- cgroup:

  cgroup version, this process's cgroup and whether it is delegated
  (writable).

- apparmor:

  Whether AppArmor is enabled and the current profile.

- tiocsti_legacy:

  Whether the kernel still lets an unprivileged process push input into
  a terminal with `TIOCSTI` (`dev.tty.legacy_tiocsti`); `NA` where the
  setting does not exist. Confined children run without a controlling
  terminal either way.

Values that do not apply on this system are `NA`.

## Examples

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
