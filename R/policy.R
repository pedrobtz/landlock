#' Build a confinement policy
#'
#' A policy is plain data: a list describing which layers to apply. The
#' builder verbs add to it and are meant to be piped. Nothing is enforced
#' until the policy is passed to [eval_safe()], [run()], [confine()] or
#' [apply_policy()].
#'
#' Layers and what they map to:
#'
#' * `fs()`: Landlock filesystem rules. Calling it at all puts the whole
#'   filesystem under Landlock: everything not listed is denied. `read`
#'   allows reading files and listing directories, `write` allows creating,
#'   writing, renaming and removing (it does not imply `read`), `exec` allows
#'   executing (and reading, which the loader needs), `rw` is `read` plus
#'   `write`. Rules apply to the path and everything beneath it. Paths must
#'   exist when the policy is applied, not when it is built.
#' * `net()`: Landlock TCP rules (kernel ABI 4). Calling it restricts TCP
#'   `bind()` and `connect()` to the listed ports; `net()` alone blocks both.
#'   UDP and Unix sockets are not affected.
#' * `scope()`: Landlock scopes (ABI 6): no signals to, and no abstract Unix
#'   socket connections with, processes outside the sandbox.
#' * `limits()`: resource limits. Each is a ceiling: when the current hard
#'   limit is already lower it is kept. `memory` limits the address space
#'   (`RLIMIT_AS`), `pids` the number of processes for the user
#'   (`RLIMIT_NPROC`), `cpu` the CPU seconds, `fsize` the largest file,
#'   `nofile` the number of open files. Sizes accept numbers of bytes or
#'   strings such as `"512m"` or `"2g"`.
#' * `ids()`: switch to another user and group (root only). Applied after
#'   every other layer except the resource limits.
#' * `apparmor()`: change to an AppArmor profile, as `unix::eval_safe(profile =)`
#'   does.
#'
#' @param best_effort If `TRUE` (the default), layers the kernel cannot
#'   provide are skipped and reported. If `FALSE`, applying the policy fails
#'   instead.
#' @param log Landlock audit logging (kernel ABI 7): `NULL` keeps the kernel
#'   default, `TRUE` also logs denials after an `exec()`, `FALSE` turns
#'   logging of denials off.
#' @return An object of class `lk_policy`.
#' @seealso [preset()] for ready-made policies, [status()] for what the
#'   kernel offers.
#' @export
#' @examples
#' p <- policy() |>
#'   fs(read = c(R.home(), .libPaths()), write = tempdir()) |>
#'   net() |>
#'   limits(memory = "2g", nofile = 256)
#' p
policy <- function(best_effort = TRUE, log = NULL) {
  stopifnot(is.logical(best_effort), length(best_effort) == 1L, !is.na(best_effort))
  if (!is.null(log)) stopifnot(is.logical(log), length(log) == 1L, !is.na(log))
  new_policy(best_effort = best_effort, log = log)
}

new_policy <- function(best_effort = TRUE, log = NULL) {
  structure(list(fs = NULL, net = NULL, scope = NULL, limits = NULL, ids = NULL,
                 apparmor = NULL, syscalls = NULL, caps = NULL,
                 best_effort = best_effort, log = log),
            class = "lk_policy")
}

check_policy <- function(p) {
  if (!inherits(p, "lk_policy")) stop("expected a policy built with policy()", call. = FALSE)
  invisible(p)
}

fs_modes <- c(read = 1L, write = 2L, exec = 4L)

#' @rdname policy
#' @param p A policy.
#' @param read,write,exec,rw Character vectors of paths.
#' @export
fs <- function(p, read = NULL, write = NULL, exec = NULL, rw = NULL) {
  check_policy(p)
  add <- function(paths, mode) {
    if (is.null(paths)) return(NULL)
    if (!is.character(paths) || anyNA(paths)) stop("fs(): paths must be a character vector")
    data.frame(path = path.expand(paths), mode = rep(mode, length(paths)), stringsAsFactors = FALSE)
  }
  new <- rbind(
    data.frame(path = character(), mode = integer(), stringsAsFactors = FALSE),
    p$fs,
    add(read, fs_modes[["read"]]),
    add(write, fs_modes[["write"]]),
    add(exec, fs_modes[["exec"]]),
    add(rw, fs_modes[["read"]] + fs_modes[["write"]])
  )
  p$fs <- new
  p
}

#' @rdname policy
#' @param bind,connect Integer vectors of TCP ports that may be bound to or
#'   connected to.
#' @export
net <- function(p, bind = integer(), connect = integer()) {
  check_policy(p)
  port <- function(x, what) {
    if (is.null(x)) return(integer())
    if (!is.numeric(x) || anyNA(x) || any(x < 0 | x > 65535 | x != round(x)))
      stop("net(): ", what, " ports must be integers between 0 and 65535")
    as.integer(x)
  }
  old <- p$net %||% list(bind = integer(), connect = integer())
  p$net <- list(bind = unique(c(old$bind, port(bind, "bind"))),
                connect = unique(c(old$connect, port(connect, "connect"))))
  p
}

#' @rdname policy
#' @param signal,abstract_unix Logical: scope signals, abstract Unix sockets.
#' @export
scope <- function(p, signal = TRUE, abstract_unix = TRUE) {
  set_scope(p, signal, abstract_unix)
}

set_scope <- function(p, signal, abstract_unix) {
  check_policy(p)
  stopifnot(is.logical(signal), length(signal) == 1L, is.logical(abstract_unix), length(abstract_unix) == 1L)
  p$scope <- list(signal = isTRUE(signal), abstract_unix = isTRUE(abstract_unix))
  p
}

#' @rdname policy
#' @param memory,cpu,fsize,nofile,pids,core,stack,data,memlock Resource
#'   ceilings; `NULL` leaves a resource alone.
#' @export
limits <- function(p, memory = NULL, cpu = NULL, fsize = NULL, nofile = NULL, pids = NULL,
                   core = NULL, stack = NULL, data = NULL, memlock = NULL) {
  check_policy(p)
  new <- list(as = parse_size(memory, "memory"), cpu = parse_size(cpu, "cpu"),
              fsize = parse_size(fsize, "fsize"), nofile = parse_size(nofile, "nofile"),
              nproc = parse_size(pids, "pids"), core = parse_size(core, "core"),
              stack = parse_size(stack, "stack"), data = parse_size(data, "data"),
              memlock = parse_size(memlock, "memlock"))
  new <- new[!vapply(new, is.null, logical(1))]
  old <- p$limits %||% list()
  old[names(new)] <- new
  p$limits <- old
  p
}

#' @rdname policy
#' @param uid,gid User and group, as numeric ids or names.
#' @export
ids <- function(p, uid = NULL, gid = NULL) {
  check_policy(p)
  p$ids <- list(uid = resolve_id(uid, "user"), gid = resolve_id(gid, "group"))
  p
}

resolve_id <- function(x, kind) {
  if (is.null(x)) return(NA_integer_)
  if (length(x) != 1L || is.na(x)) stop(kind, " must be a single id or name")
  if (is.character(x)) {
    info <- if (kind == "user") user_info(x) else group_info(x)
    return(if (kind == "user") info$uid else info$gid)
  }
  as.integer(x)
}

#' @rdname policy
#' @param profile Name of an AppArmor profile.
#' @export
apparmor <- function(p, profile) {
  check_policy(p)
  stopifnot(is.character(profile), length(profile) == 1L, !is.na(profile))
  p$apparmor <- profile
  p
}

#' @export
print.lk_policy <- function(x, ...) {
  abi <- .Call(C_ll_abi)
  avail <- function(need) if (abi >= need) "" else sprintf("  [kernel lacks this: Landlock ABI %d < %d]", abi, need)
  cat("<landlock policy>", if (isTRUE(x$best_effort)) "best effort" else "strict", "\n")
  if (!is.null(x$apparmor)) cat("  apparmor  profile", x$apparmor, "\n")
  if (!is.null(x$fs)) {
    if (!nrow(x$fs)) cat("  fs        deny everything", avail(1), "\n")
    for (m in names(fs_modes)) {
      paths <- x$fs$path[bitwAnd(x$fs$mode, fs_modes[[m]]) != 0L]
      if (length(paths)) cat(sprintf("  fs %-6s %s%s\n", m, paste(paths, collapse = ", "), avail(1)))
    }
  }
  ports <- function(v) if (length(v)) paste(v, collapse = ", ") else "none"
  if (!is.null(x$net))
    cat(sprintf("  tcp       bind: %s; connect: %s%s\n", ports(x$net$bind), ports(x$net$connect), avail(4)))
  if (!is.null(x$scope)) {
    which <- c("signal", "abstract_unix")[c(x$scope$signal, x$scope$abstract_unix)]
    if (length(which)) cat("  scope    ", paste(which, collapse = ", "), avail(6), "\n")
  }
  if (length(x$limits)) {
    shown <- vapply(names(x$limits), function(n) {
      v <- x$limits[[n]]
      paste0(n, "=", if (n %in% c("as", "fsize", "core", "stack", "data", "memlock")) format_size(v) else format(v))
    }, character(1))
    cat("  limits   ", paste(shown, collapse = ", "), "\n")
  }
  if (!is.null(x$ids)) cat("  ids       uid", x$ids$uid, "gid", x$ids$gid, "\n")
  if (length(x$syscalls)) cat("  syscalls  deny", length(x$syscalls$deny), "calls, action", x$syscalls$action, "\n")
  if (!is.null(x$caps)) cat("  caps      keep", if (length(x$caps$keep)) paste(x$caps$keep, collapse = ", ") else "none", "\n")
  invisible(x)
}
