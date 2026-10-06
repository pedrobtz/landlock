#' Restrict this process with Landlock
#'
#' A thin wrapper over the kernel's Landlock interface for the calling
#' process: the filesystem is denied except for the listed paths, TCP is
#' restricted when `tcp_bind` or `tcp_connect` is given, and the scopes are
#' applied. Irreversible. Landlock restricts the calling thread and what it
#' creates afterwards, not threads that already exist; see [confine()].
#'
#' @param read,write,exec Character vectors of paths; see [fs()].
#' @param tcp_bind,tcp_connect Integer vectors of TCP ports, or `NULL` to
#'   leave TCP alone.
#' @param scope Scopes to apply: any of `"signal"` and `"abstract_unix"`.
#' @param best_effort,log See [policy()].
#' @return The report, invisibly; see [apply_policy()].
#' @export
restrict_self <- function(read = NULL, write = NULL, exec = NULL, tcp_bind = NULL,
                          tcp_connect = NULL, scope = c("signal", "abstract_unix"),
                          best_effort = TRUE, log = NULL) {
  p <- fs(policy(best_effort = best_effort, log = log), read = read, write = write, exec = exec)
  if (!is.null(tcp_bind) || !is.null(tcp_connect))
    p <- net(p, bind = tcp_bind %||% integer(), connect = tcp_connect %||% integer())
  if (length(scope)) {
    scope <- match.arg(scope, several.ok = TRUE)
    p <- set_scope(p, signal = "signal" %in% scope, abstract_unix = "abstract_unix" %in% scope)
  }
  apply_policy(p)
}
