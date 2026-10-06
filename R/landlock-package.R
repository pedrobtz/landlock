#' landlock: process confinement for R
#'
#' Evaluate R expressions or run programs in a kernel-enforced sandbox, and
#' use every function of the 'unix' package under the same name.
#'
#' Three execution models share one [policy()]:
#'
#' * [eval_safe()] forks, restricts the child and evaluates R there;
#' * [run()] forks, restricts the child and executes a program;
#' * [confine()] restricts the current R process, irreversibly.
#'
#' [status()] reports what the running kernel offers; every enforcement
#' returns a report of the layers it applied or skipped ([last_report()]).
#'
#' @keywords internal
"_PACKAGE"

## usethis namespace: start
#' @useDynLib landlock, .registration = TRUE
#' @importFrom grDevices pdf graphics.off
#' @importFrom tools SIGHUP SIGINT SIGQUIT SIGKILL SIGTERM SIGSTOP SIGCHLD SIGUSR1 SIGUSR2
## usethis namespace: end
NULL

# Mutable package state: the last report, and in a forked child the q()
# guard and the output sinks.
.state <- new.env(parent = emptyenv())
