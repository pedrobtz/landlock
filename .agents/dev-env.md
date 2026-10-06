# Linux development environment

The maintainer's workstation is macOS. `R CMD check` and the non-Linux code
paths (every Landlock, seccomp and capability entry point compiles to a stub
returning "absent") can be exercised there directly. Everything that touches a
Linux kernel feature needs Linux.

## CI is the reference Linux environment

Every pull request runs the C harness and `R CMD check` on Linux
(`c-harness`, `R-CMD-check`, `native-checks`). The GitHub VM runners report
the Landlock ABI in the c-harness log ("Kernel and Landlock ABI" step) and run
the harness both as the runner user and as `nobody`; the container leg runs as
root. A pull request labelled `full-ci` runs the full matrix (macOS, oldrel,
valgrind, ASan, gctorture at step 20).

## Local container (optional)

A local Linux kernel shortens the loop for C work. Any of these works:

    # Podman
    podman machine init && podman machine start
    # Colima
    colima start
    # Docker Desktop or OrbStack: start the app

Then, from the repository root:

    # C harness only, no R
    docker run --rm -v "$PWD":/w -w /w ubuntu:24.04 \
      sh -c 'apt-get update -qq && apt-get install -y -qq build-essential >/dev/null && make -C tests/c && tests/c/run'

    # R package
    docker run --rm -v "$PWD":/w -w /w rocker/r-ver:4.5 \
      sh -c 'R CMD INSTALL . && Rscript -e "landlock::status()"'

Docker's default seccomp profile allows the `landlock_*` and `seccomp`
system calls, so Landlock, seccomp, capabilities and rlimits are all testable
in a container. Whether Landlock is available at all depends on the VM's
kernel: `landlock::status()$landlock_abi` (or the harness's first line) says.

Known local state, 2026-10-06: the existing `podman-machine-default` VM fails
to start ("qmp_podman-machine-default.sock: no such file or directory");
`podman machine rm` and `podman machine init` would recreate it. CI was used
instead.
