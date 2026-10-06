# Capabilities and no_new_privs

`caps_drop_all()` empties the capability bounding set (so nothing can
regain a capability, which needs `CAP_SETPCAP` and so only works for a
privileged process), clears the effective, permitted, inheritable and
ambient sets, and sets `no_new_privs`. `caps_keep()` does the same but
keeps the named capabilities. Irreversible. Linux only.

## Usage

``` r
caps_drop_all()

caps_keep(...)

no_new_privs()
```

## Arguments

- ...:

  Capability names, with or without the `CAP_` prefix, in any case:
  `"net_bind_service"`, `"CAP_SYS_CHROOT"`.

## Value

`caps_drop_all()` and `caps_keep()`: `TRUE` if the bounding set was
emptied, `FALSE` if the process lacked the privilege to do so,
invisibly. `no_new_privs()`: `TRUE`, invisibly.

## Details

`no_new_privs()` sets the `no_new_privs` flag: neither the process nor
its children can gain privileges through `execve()` (set-user-id
programs, file capabilities). Landlock and seccomp set it as well.

## Examples

``` r
# Irreversible, so shown in a throwaway child; Linux only.
if (Sys.info()[["sysname"]] == "Linux") {
  eval_fork({
    caps_drop_all()
    status()$caps$effective
  })
}
#> [1] "0000000000000000"
```
