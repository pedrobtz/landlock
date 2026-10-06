#' Process information
#'
#' Get or set attributes of the current process, with the same names,
#' arguments and results as the 'unix' package.
#'
#' * `pid`: process id; `ppid`: parent process id; `pgid`: process group id.
#' * `uid`, `euid`: real and effective user id; `gid`, `egid`: group ids.
#' * `prio`: scheduling priority; a higher value is a lower priority.
#'
#' An unprivileged process cannot change its `uid` and can only lower its
#' priority (raise the value).
#'
#' @param uid User id.
#' @param gid Group id.
#' @param pgid Process group id; `0` uses the current process id.
#' @param prio Priority.
#' @param pid Process id.
#' @param signal Signal number, [tools::SIGTERM] by default.
#' @return The getters and setters return the (new) value as an integer;
#'   `kill()` returns `NULL`.
#' @references [GETUID(2)](https://man7.org/linux/man-pages/man2/getuid.2.html)
#'   [GETPID(2)](https://man7.org/linux/man-pages/man2/getpid.2.html)
#'   [GETPGID(2)](https://man7.org/linux/man-pages/man2/getpgid.2.html)
#'   [GETPRIORITY(2)](https://man7.org/linux/man-pages/man2/getpriority.2.html)
#' @name process
#' @examples
#' getuid()
#' getpid()
#' getpriority()
NULL

#' @rdname process
#' @export
getuid <- function() .Call(C_getid, 0L)

#' @rdname process
#' @export
getgid <- function() .Call(C_getid, 2L)

#' @rdname process
#' @export
geteuid <- function() .Call(C_getid, 1L)

#' @rdname process
#' @export
getegid <- function() .Call(C_getid, 3L)

#' @rdname process
#' @export
getpid <- function() .Call(C_getpid)

#' @rdname process
#' @export
getppid <- function() .Call(C_getppid)

#' @rdname process
#' @export
getpgid <- function() .Call(C_getpgid)

#' @rdname process
#' @export
getpriority <- function() .Call(C_getpriority)

#' @rdname process
#' @export
setuid <- function(uid) {
  stopifnot(is.numeric(uid))
  .Call(C_setid, 0L, as.integer(uid))
}

#' @rdname process
#' @export
seteuid <- function(uid) {
  .Call(C_setid, 1L, as.integer(uid))
}

#' @rdname process
#' @export
setgid <- function(gid) {
  stopifnot(is.numeric(gid))
  .Call(C_setid, 2L, as.integer(gid))
}

#' @rdname process
#' @export
setegid <- function(gid) {
  .Call(C_setid, 3L, as.integer(gid))
}

#' @rdname process
#' @export
setpgid <- function(pgid = 0) {
  .Call(C_setpgid, as.integer(pgid))
}

#' @rdname process
#' @export
setpriority <- function(prio) {
  stopifnot(is.numeric(prio))
  .Call(C_setpriority, as.integer(prio))
}

#' @rdname process
#' @export
kill <- function(pid, signal = SIGTERM) {
  stopifnot(is.numeric(pid), is.numeric(signal))
  .Call(C_kill, as.integer(pid), as.integer(signal))
}

#' Package configuration
#'
#' `sys_config()` reports which features this build supports, and
#' `aa_config()` the AppArmor state, with the shapes the 'unix' package uses.
#' This package needs no build-time configuration: forking with output
#' capture is always available (`safe`), and AppArmor is used through
#' `/proc` on Linux without 'libapparmor' (`apparmor`).
#'
#' @return `sys_config()`: a list with logical elements `safe` and
#'   `apparmor`. `aa_config()`: a list with `compiled` (AppArmor support in
#'   this build), `enabled`, and the current profile `con` and its `mode`
#'   (`NULL` when unknown).
#' @export
#' @examples
#' sys_config()
#' aa_config()
sys_config <- function() {
  list(safe = safe_build(), apparmor = is_linux())
}

safe_build <- function() TRUE

# A C loop that ignores interrupts unless asked: long-running native code,
# for the tests (unix's freeze()).
freeze <- function(interrupt = TRUE) {
  .Call(C_freeze, as.logical(interrupt))
}
