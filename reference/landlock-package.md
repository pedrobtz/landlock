# landlock: Process Confinement with 'Landlock', 'seccomp' and Capabilities

Evaluate R expressions or run programs in a kernel-enforced sandbox.
Builds on 'Landlock' <https://landlock.io/> (filesystem and TCP rules),
'seccomp-bpf' (system call filters), capability dropping and resource
limits, without external libraries. Degrades gracefully with a report
when a feature is unavailable. A drop-in replacement for the 'unix'
package: every function it exports is provided with the same name and
arguments.

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
