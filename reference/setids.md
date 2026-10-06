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
