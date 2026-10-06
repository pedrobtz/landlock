# Change AppArmor profile

Asks AppArmor to move the calling process into another profile, by
writing to `/proc/self/attr/apparmor/current` as 'libapparmor' does. The
profile must be loaded and must allow the change. Irreversible unless
the target profile allows changing back.

## Usage

``` r
aa_change_profile(profile)
```

## Arguments

- profile:

  Name of the profile.

## Value

`NULL`, invisibly.

## Examples

``` r
# Needs AppArmor and a loaded profile; irreversible, so in a child.
if (isTRUE(aa_config()$enabled)) {
  try(eval_fork(aa_change_profile("unconfined")))
}
#> NULL
```
