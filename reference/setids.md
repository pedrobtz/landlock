# Switch user and group

Sets the supplementary groups (root only), then the real, effective and
saved group id, then the user id, so the process cannot switch back.

## Usage

``` r
setids(uid = NULL, gid = NULL)
```

## Arguments

- uid, gid:

  User and group as numeric ids or names; `NULL` keeps the current one.

## Value

`NULL`, invisibly.

## Examples

``` r
# Root only, irreversible: shown in a throwaway child.
if (getuid() == 0) {
  eval_fork({
    setids(65534, 65534)
    c(getuid(), getgid())
  })
}
```
