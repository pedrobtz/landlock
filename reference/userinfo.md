# User and group information

Look up a user or a group by id or name, with the same results as the
'unix' package.

## Usage

``` r
user_info(uid = getuid())

group_info(gid = getgid())
```

## Arguments

- uid:

  User id (integer) or name (string).

- gid:

  Group id (integer) or name (string).

## Value

`user_info()`: a list with `name`, `passwd`, `uid`, `gid`, `gecos`,
`dir` and `shell`. `group_info()`: a list with `name`, `passwd`, `gid`
and `members`.

## References

[GETPWNAM(3)](https://man7.org/linux/man-pages/man3/getpwnam.3.html)
[GETGRNAM(3)](https://man7.org/linux/man-pages/man3/getgrnam.3.html)

## Examples

``` r
user_info()
#> $name
#> [1] "runner"
#> 
#> $passwd
#> [1] "x"
#> 
#> $uid
#> [1] 1001
#> 
#> $gid
#> [1] 1001
#> 
#> $gecos
#> [1] ""
#> 
#> $dir
#> [1] "/home/runner"
#> 
#> $shell
#> [1] "/bin/bash"
#> 
group_info()
#> $name
#> [1] "runner"
#> 
#> $passwd
#> [1] "x"
#> 
#> $gid
#> [1] 1001
#> 
#> $members
#> character(0)
#> 
```
