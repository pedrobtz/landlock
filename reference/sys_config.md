# Package configuration

`sys_config()` reports which features this build supports, and
`aa_config()` the AppArmor state, with the shapes the 'unix' package
uses. This package needs no build-time configuration: forking with
output capture is always available (`safe`), and AppArmor is used
through `/proc` on Linux without 'libapparmor' (`apparmor`).

## Usage

``` r
aa_config()

sys_config()
```

## Value

`sys_config()`: a list with logical elements `safe` and `apparmor`.
`aa_config()`: a list with `compiled` (AppArmor support in this build),
`enabled`, and the current profile `con` and its `mode` (`NULL` when
unknown).

## Examples

``` r
sys_config()
#> $safe
#> [1] TRUE
#> 
#> $apparmor
#> [1] TRUE
#> 
aa_config()
#> $compiled
#> [1] TRUE
#> 
#> $enabled
#> [1] TRUE
#> 
#> $con
#> [1] "unconfined"
#> 
#> $mode
#> NULL
#> 
```
