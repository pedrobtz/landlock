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
#' @examples
#' seccomp_status()
#' head(syscall_table())
#'
#' # Irreversible, so shown in a throwaway child; Linux only.
#' if (Sys.info()[["sysname"]] == "Linux") {
#'   eval_fork({
#'     seccomp_deny("getppid")
#'     getppid()  # -1: the call failed with EPERM
#'   })
#' }
#' @export
seccomp_deny <- function(syscalls, action = c("errno", "kill", "log", "trap"), errno = "EPERM") {
  spec <- syscall_spec(syscalls, action, errno)
  spec$block_tty <- FALSE
  spec$lock_personality <- FALSE
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

sc_families <- c(unix = 0L, inet = 0L, inet6 = 0L, netlink = 0L, packet = 0L, vsock = 0L)

# personality() values Docker's default profile allows: PER_LINUX,
# PER_LINUX32, UNAME26, PER_LINUX32 | UNAME26, and the query 0xffffffff.
sc_personalities <- c(0, 8, 0x20000, 0x20008, 0xffffffff)

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
         "EINVAL, ENOTSUP, EAGAIN, ENOMEM, EIO, EFAULT, EAFNOSUPPORT", call. = FALSE)
  list(deny = unique(syscalls), action = action, errno = errnum,
       errno_name = if (is.character(errno)) errno else as.character(errnum))
}

# Returns list(status, detail, tsync); strict errors instead of skipping.
# The rules a filter spec turns into on this architecture, in filter order:
# argument rules first (a call they do not match falls through to the plain
# deny list), then the plain denies. Used to install and to list.
filter_rules <- function(spec) {
  nrs <- .Call(C_sc_lookup, spec$deny)
  absent <- spec$deny[nrs == -1L]
  names <- spec$deny[nrs >= 0L]
  nrs <- nrs[nrs >= 0L]
  actions <- rep(sc_actions[[spec$action]], length(nrs))
  errnos <- rep(spec$errno, length(nrs))
  # clone3 must fail with ENOSYS, whatever the action: the C library then
  # falls back to clone(), whose flags the filter can inspect (clone3 passes
  # them in memory, out of a filter's reach). Any other answer would break
  # thread and process creation.
  is_clone3 <- names == "clone3"
  actions[is_clone3] <- sc_actions[["errno"]]
  errnos[is_clone3] <- .Call(C_errno_value, "ENOSYS")
  # Denying unshare is meant to deny new namespaces; clone() can create them
  # too, so the filter also refuses clone() with any CLONE_NEW* flag.
  clone_ns <- "unshare" %in% spec$deny
  args <- rep(-1L, length(nrs))
  negates <- rep(0L, length(nrs))
  vals <- vector("list", length(nrs))
  extra <- character()
  arg_rule <- function(name, arg, values, negate, errno_name) {
    nr <- .Call(C_sc_lookup, name)
    if (nr < 0L) return(FALSE)
    names <<- c(name, names)
    nrs <<- c(nr, nrs)
    actions <<- c(sc_actions[["errno"]], actions)
    errnos <<- c(.Call(C_errno_value, errno_name), errnos)
    args <<- c(arg, args)
    negates <<- c(as.integer(negate), negates)
    vals <<- c(list(as.double(values)), vals)
    TRUE
  }
  if (isTRUE(spec$block_tty)) {
    req <- .Call(C_tty_ioctls)
    req <- req[!is.na(req)]
    if (length(req) && arg_rule("ioctl", 1L, req, FALSE, "EPERM"))
      extra <- c(extra, "terminal injection ioctls refused")
  }
  if (length(spec$socket_families)) {
    fam <- vapply(spec$socket_families, function(f) .Call(C_af_value, f), integer(1))
    if (arg_rule("socket", 0L, fam[!is.na(fam)], TRUE, "EAFNOSUPPORT"))
      extra <- c(extra, paste("sockets limited to", paste(spec$socket_families, collapse = ", ")))
    sc_nr <- .Call(C_sc_lookup, "socketcall")
    if (sc_nr >= 0L) {
      names <- c(names, "socketcall")
      nrs <- c(nrs, sc_nr)
      actions <- c(actions, sc_actions[["errno"]])
      errnos <- c(errnos, .Call(C_errno_value, "EPERM"))
      args <- c(args, -1L)
      negates <- c(negates, 0L)
      vals <- c(vals, list(NULL))
    }
  }
  if (isTRUE(spec$lock_personality) && !"personality" %in% spec$deny) {
    if (arg_rule("personality", 0L, sc_personalities, TRUE, "EPERM"))
      extra <- c(extra, "personality locked")
  }
  list(name = names, nr = nrs, action = actions, errno = errnos, arg = args, negate = negates,
       vals = vals, absent = absent, extra = extra, clone_ns = clone_ns)
}

#' The seccomp filter a policy produces
#'
#' Lists the rules the `syscalls()` layer of a policy installs on this
#' architecture, in the order the filter checks them, like 'libseccomp''s
#' `seccomp_export_pfc()`. Every filter also starts by killing calls made for
#' another architecture (and, on x86_64, x32 calls), and allows any call no
#' rule matches.
#'
#' @param p A [policy()] with a `syscalls()` layer.
#' @return A data frame with one row per rule: `call`, its number `nr` on
#'   this architecture, the `condition` on its arguments (empty when every
#'   call is matched), and the `result` (`"errno EPERM"`, `"kill"`, ...).
#'   Calls that do not exist on this architecture are listed in the
#'   attribute `absent`. Empty off Linux.
#' @export
#' @examples
#' seccomp_rules(preset("numeric"))
seccomp_rules <- function(p) {
  check_policy(p)
  if (is.null(p$syscalls)) stop("the policy has no syscalls() layer", call. = FALSE)
  empty <- data.frame(call = character(), nr = integer(), condition = character(),
                      result = character(), stringsAsFactors = FALSE)
  if (!is_linux()) return(empty)
  fr <- filter_rules(p$syscalls)
  errno_name <- function(e) {
    known <- c("EPERM", "EACCES", "ENOSYS", "EINVAL", "EAFNOSUPPORT", "EIO", "EAGAIN", "ENOMEM")
    vals <- vapply(known, function(k) .Call(C_errno_value, k), integer(1))
    if (e %in% vals) known[match(e, vals)] else paste("errno", e)
  }
  result <- vapply(seq_along(fr$nr), function(i) {
    a <- names(sc_actions)[match(fr$action[i], sc_actions)]
    if (a == "errno") paste("errno", errno_name(fr$errno[i])) else a
  }, character(1))
  condition <- vapply(seq_along(fr$nr), function(i) {
    if (fr$arg[i] < 0L) return("")
    v <- paste(sprintf("0x%x", as.numeric(fr$vals[[i]])), collapse = ", ")
    sprintf("arg%d %s {%s}", fr$arg[i], if (fr$negate[i] == 1L) "not in" else "in", v)
  }, character(1))
  out <- data.frame(call = fr$name, nr = fr$nr, condition = condition, result = result,
                    stringsAsFactors = FALSE)
  if (fr$clone_ns && .Call(C_sc_lookup, "clone") >= 0L)
    out <- rbind(data.frame(call = "clone", nr = .Call(C_sc_lookup, "clone"),
                            condition = "flags include CLONE_NEW*", result = "errno EPERM",
                            stringsAsFactors = FALSE), out)
  structure(out, absent = fr$absent)
}

install_filter <- function(spec, strict) {
  if (!is_linux()) {
    if (strict) stop("seccomp is only available on Linux", call. = FALSE)
    return(list(status = "skipped", detail = "seccomp is only available on Linux", tsync = FALSE))
  }
  fr <- filter_rules(spec)
  nrs <- fr$nr; actions <- fr$action; errnos <- fr$errno
  args <- fr$arg; negates <- fr$negate; vals <- fr$vals
  absent <- fr$absent; extra <- fr$extra; clone_ns <- fr$clone_ns
  rc <- .Call(C_sc_install, nrs, as.integer(actions), as.integer(errnos), as.integer(args),
              as.integer(negates), vals, clone_ns)
  if (rc[[1]] == -.Call(C_errno_value, "ENOTSUP")) {
    msg <- "seccomp filters are not supported on this architecture by this build"
    if (strict) stop(msg, call. = FALSE)
    return(list(status = "skipped", detail = msg, tsync = FALSE))
  }
  if (rc[[1]] != 0L)
    stop("installing the seccomp filter: ", .Call(C_strerror, rc[[1]]), call. = FALSE)
  plain <- sum(args < 0L)
  detail <- sprintf("deny %d call%s (%s%s)", plain, if (plain == 1L) "" else "s",
                    spec$action, if (spec$action == "errno") paste0(" ", spec$errno_name) else "")
  if (length(extra)) detail <- paste0(detail, "; ", paste(extra, collapse = "; "))
  if (length(absent))
    detail <- paste0(detail, "; not on this architecture: ", paste(absent, collapse = ", "))
  if (clone_ns) detail <- paste0(detail, "; clone() with namespace flags refused")
  if (rc[[2]] == 0L) detail <- paste0(detail, "; calling thread only")
  list(status = "applied", detail = detail, tsync = rc[[2]] == 1L)
}
