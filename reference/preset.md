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

A [`policy()`](https://pedrobtz.github.io/landlock/reference/policy.md).

## Details

- `"numeric"`: evaluate R code that only computes. Reads R, the
  installed packages and system libraries; reads and writes only the
  session's temporary directory; may execute nothing; no TCP; signals
  and abstract sockets scoped to the sandbox.

- `"install"`: install a package from source. As `"numeric"`, plus
  executing the compiler toolchain (and the dynamic loader, which the
  kernel opens for execution too) and writing to `lib`.

- `"plumber"`: serve HTTP. As `"numeric"`, plus binding to `port`.

Paths that do not exist on this system are left out.

## Examples

``` r
preset("numeric")
#> <landlock policy> best effort 
#>   fs read   /opt/R/4.6.1/lib/R, /home/runner/work/_temp/Library, /opt/R/4.6.1/lib/R/site-library, /opt/R/4.6.1/lib/R/library, /usr, /lib, /lib64, /opt/R, /etc/ld.so.cache, /etc/localtime, /etc/timezone, /etc/os-release, /dev/urandom, /dev/null, /tmp/Rtmp7UXASl, /dev/null
#>   fs write  /tmp/Rtmp7UXASl, /dev/null
#>   tcp       bind: none; connect: none
#>   scope     signal, abstract_unix  
```
