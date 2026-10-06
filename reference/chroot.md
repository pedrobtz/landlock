# Change root directory

Changes the root directory of the calling process, then its working
directory to the new root. Only a privileged process may call it. As the
'unix' package notes, `chroot()` is not a security boundary on its own;
combine it with a
[`policy()`](https://pedrobtz.github.io/landlock/reference/policy.md).
Afterwards R can only use code already in memory: base R and this
package are loaded before
[`eval_fork()`](https://pedrobtz.github.io/landlock/reference/eval_safe.md)
and
[`eval_safe()`](https://pedrobtz.github.io/landlock/reference/eval_safe.md)
fork, functions of other packages used for the first time are not.

## Usage

``` r
chroot(path = getwd())
```

## Arguments

- path:

  Directory of the new root.

## Value

`path`, normalized.

## References

[CHROOT(2)](https://man7.org/linux/man-pages/man2/chroot.2.html)

## Examples

``` r
# Root only, irreversible: shown in a throwaway child.
if (getuid() == 0) {
  eval_fork({
    chroot(tempdir())
    file.exists("/etc/passwd")
  })
}
```
