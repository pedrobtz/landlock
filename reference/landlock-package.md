# landlock: process confinement for R

Evaluate R expressions or run programs in a kernel-enforced sandbox, and
use every function of the 'unix' package under the same name.

## Details

Three execution models share one
[`policy()`](https://pedrobtz.github.io/landlock/reference/policy.md):

- [`eval_safe()`](https://pedrobtz.github.io/landlock/reference/eval_safe.md)
  forks, restricts the child and evaluates R there;

- [`run()`](https://pedrobtz.github.io/landlock/reference/run.md) forks,
  restricts the child and executes a program;

- [`confine()`](https://pedrobtz.github.io/landlock/reference/apply_policy.md)
  restricts the current R process, irreversibly.

[`status()`](https://pedrobtz.github.io/landlock/reference/status.md)
reports what the running kernel offers; every enforcement returns a
report of the layers it applied or skipped
([`last_report()`](https://pedrobtz.github.io/landlock/reference/last_report.md)).

## See also

Useful links:

- <https://pedrobtz.github.io/landlock/>

- <https://github.com/pedrobtz/landlock>

- Report bugs at <https://github.com/pedrobtz/landlock/issues>

## Author

**Maintainer**: Pedro Z <pedrobtz@gmail.com>

Authors:

- Pedro Z <pedrobtz@gmail.com>

Other contributors:

- Jeroen Ooms (Author of the 'unix' package test suite ported in
  tests/testthat) \[copyright holder\]
