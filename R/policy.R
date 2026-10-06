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
#' * `syscalls()`: a seccomp filter denying the listed system calls; see
#'   [seccomp_deny()] for the actions and [preset()] for ready-made sets.
#'   Calling `syscalls()` again adds to the list.
#' * `caps()`: drop every capability except `keep` and set `no_new_privs`;
#'   see [caps_drop_all()].
#' * `umask()`: the file mode creation mask of the child, so that files it
#'   creates get the intended permissions.
#' * `deny_write_execute()`: no memory mapping may become both writable and
#'   executable (Linux 6.3, `PR_SET_MDWE`), which stops code injected into
#'   writable memory from running. Breaks just-in-time compilers (V8, LLVM);
#'   no preset uses it.
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
  structure(list(fs = NULL, fs_tmp = FALSE, fs_missing = "error", net = NULL, scope = NULL,
                 limits = NULL, ids = NULL, apparmor = NULL, syscalls = NULL, caps = NULL,
                 mdwe = FALSE, umask = NULL,
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
#' @param missing What to do, when the policy is applied, with a path that
#'   does not exist: `"error"` (the default) or `"ignore"` it, naming it in
#'   the report. Useful for policies shared between machines.
#' @param tmp If `TRUE`, also allow reading and writing the call's own
#'   temporary directory: `tmp` of [eval_safe()], the child's `TMPDIR`. It is
#'   created for the call and, by default, removed afterwards. The session's
#'   [tempdir()] is deliberately not granted: the session may later trust
#'   what it finds there.
#' @export
fs <- function(p, read = NULL, write = NULL, exec = NULL, rw = NULL, tmp = FALSE,
               missing = c("error", "ignore")) {
  check_policy(p)
  p$fs_missing <- match.arg(missing)
  stopifnot(is.logical(tmp), length(tmp) == 1L, !is.na(tmp))
  if (tmp) p$fs_tmp <- TRUE
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
#' @param rss,locks,sigpending,msgqueue,nice,rtprio,rttime Further
#'   resource limits (Linux): resident set size, file locks, queued signals,
#'   bytes in POSIX message queues, the nice ceiling (as `20 - value`),
#'   real-time priority (`0` forbids real-time scheduling) and real-time CPU
#'   time in microseconds. A limit the platform lacks is skipped and reported.
#' @export
limits <- function(p, memory = NULL, cpu = NULL, fsize = NULL, nofile = NULL, pids = NULL,
                   core = NULL, stack = NULL, data = NULL, memlock = NULL, rss = NULL,
                   locks = NULL, sigpending = NULL, msgqueue = NULL, nice = NULL,
                   rtprio = NULL, rttime = NULL) {
  check_policy(p)
  new <- list(as = parse_size(memory, "memory"), cpu = parse_size(cpu, "cpu"),
              fsize = parse_size(fsize, "fsize"), nofile = parse_size(nofile, "nofile"),
              nproc = parse_size(pids, "pids"), core = parse_size(core, "core"),
              stack = parse_size(stack, "stack"), data = parse_size(data, "data"),
              memlock = parse_size(memlock, "memlock"), rss = parse_size(rss, "rss"),
              locks = parse_size(locks, "locks"), sigpending = parse_size(sigpending, "sigpending"),
              msgqueue = parse_size(msgqueue, "msgqueue"), nice = parse_size(nice, "nice"),
              rtprio = parse_size(rtprio, "rtprio"), rttime = parse_size(rttime, "rttime"))
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
  p$ids <- resolve_ids(uid, gid)
  p
}

# A uid without a gid takes the user's primary group, so root switching
# user never keeps group 0 (and the supplementary groups are replaced).
resolve_ids <- function(uid, gid) {
  u <- resolve_id(uid, "user")
  g <- resolve_id(gid, "group")
  if (!is.na(u) && is.na(g)) g <- user_info(u)$gid
  list(uid = u, gid = g)
}

resolve_id <- function(x, kind) {
  if (is.null(x)) return(NA_integer_)
  if (length(x) != 1L || is.na(x)) stop(kind, " must be a single id or name", call. = FALSE)
  if (is.character(x)) {
    info <- if (kind == "user") user_info(x) else group_info(x)
    return(if (kind == "user") info$uid else info$gid)
  }
  if (!is.numeric(x) || x < 0 || x > .Machine$integer.max || x != round(x))
    stop(kind, " id must be a whole number between 0 and ", .Machine$integer.max, call. = FALSE)
  as.integer(x)
}

#' @rdname policy
#' @param mask File mode creation mask, as for [Sys.umask()], for example
#'   `"077"` so that every file the child creates is private.
#' @export
umask <- function(p, mask) {
  check_policy(p)
  mode <- if (length(mask) == 1L) tryCatch(as.octmode(mask), error = function(e) NA) else NA
  if (is.na(mode) || mode > as.octmode("777"))
    stop("umask(): mask must be an octal mode such as \"077\"", call. = FALSE)
  p$umask <- format(mode)
  p
}

#' @rdname policy
#' @export
deny_write_execute <- function(p) {
  check_policy(p)
  p$mdwe <- TRUE
  p
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

#' @rdname policy
#' @param deny Character vector of system call names.
#' @param action,errno See [seccomp_deny()].
#' @param block_tty If `TRUE`, refuse the `ioctl()` requests that push input
#'   into a terminal or reprogram it (`TIOCSTI`, `TIOCLINUX`), as Flatpak
#'   does.
#' @param socket_families If not `NULL`, `socket()` may only create sockets
#'   of these families (any of `"unix"`, `"inet"`, `"inet6"`, `"netlink"`,
#'   `"packet"`, `"vsock"`); others fail with `EAFNOSUPPORT`. On i386 the C
#'   library creates sockets through `socketcall()`, which hides the family
#'   from the filter; `socketcall()` is then refused outright, so no socket
#'   of any family can be created there.
#' @param lock_personality If `TRUE`, `personality()` may only query or set
#'   the default execution domains, as in Docker's profile: no turning off
#'   address-space randomization.
#' @export
syscalls <- function(p, deny = character(), action = c("errno", "kill", "log", "trap"),
                     errno = "EPERM", block_tty = FALSE, socket_families = NULL,
                     lock_personality = FALSE) {
  check_policy(p)
  spec <- syscall_spec(deny, action, errno)
  stopifnot(is.logical(block_tty), length(block_tty) == 1L, !is.na(block_tty),
            is.logical(lock_personality), length(lock_personality) == 1L, !is.na(lock_personality))
  if (!is.null(socket_families)) {
    socket_families <- match.arg(socket_families, names(sc_families), several.ok = TRUE)
  }
  old <- p$syscalls
  if (!is.null(old)) spec$deny <- unique(c(old$deny, spec$deny))
  spec$block_tty <- block_tty || isTRUE(old$block_tty)
  spec$lock_personality <- lock_personality || isTRUE(old$lock_personality)
  spec$socket_families <- socket_families %||% old$socket_families
  p$syscalls <- spec
  p
}

#' @rdname policy
#' @param keep Capability names to keep; see [caps_keep()].
#' @export
caps <- function(p, keep = character()) {
  check_policy(p)
  cap_numbers(keep)
  p$caps <- list(keep = keep)
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
  if (isTRUE(x$fs_tmp)) cat("  fs tmp    the call's own temporary directory (read and write)", avail(1), "\n")
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
  if (length(x$syscalls)) {
    extra <- c(if (isTRUE(x$syscalls$block_tty)) "terminal injection blocked",
               if (length(x$syscalls$socket_families)) paste("sockets:", paste(x$syscalls$socket_families, collapse = ", ")),
               if (isTRUE(x$syscalls$lock_personality)) "personality locked")
    cat("  syscalls  deny", length(x$syscalls$deny), "calls, action", x$syscalls$action,
        if (length(extra)) paste0("; ", paste(extra, collapse = "; ")), "\n")
  }
  if (isTRUE(x$mdwe)) cat("  memory    no writable and executable mappings\n")
  if (!is.null(x$umask)) cat("  umask    ", x$umask, "\n")
  if (!is.null(x$caps)) cat("  caps      keep", if (length(x$caps$keep)) paste(x$caps$keep, collapse = ", ") else "none", "\n")
  invisible(x)
}
