#' System call filters
#'
#' `seccomp_deny()` installs a seccomp-bpf filter on the calling process
#' that makes the listed system calls fail (or kills the process) and
#' allows every other call. Filters stack and cannot be removed; it also
#' sets `no_new_privs`. Calls made for another architecture's ABI (32-bit
#' calls on a 64-bit kernel) are always refused. Linux only.
#'
#' The filter goes to every thread of the process when the kernel can do
#' that (seccomp's TSYNC flag), otherwise only to the calling thread.
#'
#' Two calls get special treatment. `clone3` always fails with `ENOSYS`, so
#' the C library falls back to `clone()`, whose flags a filter can inspect.
#' Denying `unshare` also refuses `clone()` with any namespace flag, which
#' would otherwise create the same namespaces.
#'
#' Actions: `"errno"` makes the call fail with `errno` (default `EPERM`),
#' `"kill"` kills the process with `SIGSYS`, `"log"` allows the call but
#' logs it to the kernel audit log, `"trap"` sends `SIGSYS` to the thread.
#'
#' `syscall_table()` lists the system calls this build knows for this
#' architecture; [preset()] provides the sets `"dangerous"`, `"no_exec"` and
#' `"no_net"`. `seccomp_status()` reports the filter state of this process.
#'
#' @param syscalls Character vector of system call names. Names that exist
#'   only on other architectures are ignored.
#' @param action What happens on a denied call; see Details.
#' @param errno Error returned by `action = "errno"`: a name such as
#'   `"EPERM"` or `"EACCES"`, or a number.
#' @return `seccomp_deny()`: `TRUE` if every thread got the filter, `FALSE`
#'   if only the calling one, invisibly. `seccomp_status()`: a list with the
#'   `mode` (0 none, 1 strict, 2 filter) and the number of `filters`.
#'   `syscall_table()`: a data frame with `name` and `nr`.
#' @export
seccomp_deny <- function(syscalls, action = c("errno", "kill", "log", "trap"), errno = "EPERM") {
  spec <- syscall_spec(syscalls, action, errno)
  res <- install_filter(spec, strict = TRUE)
  invisible(res$tsync)
}

#' @rdname seccomp_deny
#' @export
seccomp_status <- function() {
  st <- proc_status()
  filters <- if ("Seccomp_filters" %in% names(st)) as.integer(st[["Seccomp_filters"]]) else NA_integer_
  list(mode = .Call(C_sc_status), filters = filters)
}

#' @rdname seccomp_deny
#' @export
syscall_table <- function() {
  t <- .Call(C_sc_table)
  data.frame(name = t[[1]], nr = t[[2]], stringsAsFactors = FALSE)
}

sc_actions <- c(errno = 0L, kill = 1L, log = 2L, trap = 3L)

syscall_spec <- function(syscalls, action, errno) {
  if (!is.character(syscalls) || anyNA(syscalls))
    stop("system calls must be given as a character vector of names", call. = FALSE)
  unknown <- setdiff(syscalls, syscall_names)
  if (length(unknown))
    stop("unknown system call: ", paste(unknown, collapse = ", "),
         " (see tools/syscalls.txt in the package sources)", call. = FALSE)
  action <- match.arg(action, names(sc_actions))
  errnum <- if (is.numeric(errno)) as.integer(errno) else .Call(C_errno_value, errno)
  if (length(errnum) != 1L || is.na(errnum) || errnum < 1L || errnum > 4095L)
    stop("errno must be a number between 1 and 4095 or one of EPERM, EACCES, ENOSYS, ",
         "EINVAL, ENOTSUP, EAGAIN, ENOMEM, EIO", call. = FALSE)
  list(deny = unique(syscalls), action = action, errno = errnum,
       errno_name = if (is.character(errno)) errno else as.character(errnum))
}

# Returns list(status, detail, tsync); strict errors instead of skipping.
install_filter <- function(spec, strict) {
  if (!is_linux()) {
    if (strict) stop("seccomp is only available on Linux", call. = FALSE)
    return(list(status = "skipped", detail = "seccomp is only available on Linux", tsync = FALSE))
  }
  nrs <- .Call(C_sc_lookup, spec$deny)
  absent <- spec$deny[nrs == -1L]
  present <- spec$deny[nrs >= 0L]
  nrs <- nrs[nrs >= 0L]
  actions <- rep(sc_actions[[spec$action]], length(nrs))
  errnos <- rep(spec$errno, length(nrs))
  # clone3 must fail with ENOSYS, whatever the action: the C library then
  # falls back to clone(), whose flags the filter can inspect (clone3 passes
  # them in memory, out of a filter's reach). Any other answer would break
  # thread and process creation.
  is_clone3 <- present == "clone3"
  actions[is_clone3] <- sc_actions[["errno"]]
  errnos[is_clone3] <- .Call(C_errno_value, "ENOSYS")
  # Denying unshare is meant to deny new namespaces; clone() can create them
  # too, so refuse clone() with any CLONE_NEW* flag as well.
  clone_ns <- "unshare" %in% spec$deny
  rc <- .Call(C_sc_install, nrs, as.integer(actions), as.integer(errnos), clone_ns)
  if (rc[[1]] == -.Call(C_errno_value, "ENOTSUP")) {
    msg <- "seccomp filters are not supported on this architecture by this build"
    if (strict) stop(msg, call. = FALSE)
    return(list(status = "skipped", detail = msg, tsync = FALSE))
  }
  if (rc[[1]] != 0L)
    stop("installing the seccomp filter: ", .Call(C_strerror, rc[[1]]), call. = FALSE)
  detail <- sprintf("deny %d call%s (%s%s)", sum(nrs >= 0L), if (sum(nrs >= 0L) == 1L) "" else "s",
                    spec$action, if (spec$action == "errno") paste0(" ", spec$errno_name) else "")
  if (length(absent))
    detail <- paste0(detail, "; not on this architecture: ", paste(absent, collapse = ", "))
  if (clone_ns) detail <- paste0(detail, "; clone() with namespace flags refused")
  if (rc[[2]] == 0L) detail <- paste0(detail, "; calling thread only")
  list(status = "applied", detail = detail, tsync = rc[[2]] == 1L)
}
