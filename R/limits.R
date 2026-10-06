#' Resource limits
#'
#' Get and set process resource limits, with the same names, arguments and
#' results as the 'unix' package. Each function returns the current limits
#' and can optionally update them. `rlimit_all()` returns every limit.
#'
#' Each resource has a soft limit (`cur`), which the kernel enforces, and a
#' hard limit (`max`), the ceiling for the soft limit. An unprivileged process
#' may set its soft limit anywhere up to the hard limit and may lower its hard
#' limit, irreversibly. Setting `cur` above the current `max` also tries to
#' raise `max`, which only a privileged process may do.
#'
#' * `as`: the maximum size of the virtual address space, in bytes.
#' * `core`: the maximum size of a core dump.
#' * `cpu`: CPU time in seconds; the process receives `SIGXCPU` at the soft
#'   limit.
#' * `data`: the maximum size of the data segment.
#' * `fsize`: the largest file the process may create.
#' * `memlock`: bytes of memory that may be locked into RAM.
#' * `nofile`: one more than the largest file descriptor number.
#' * `nproc`: processes for the real user id; not enforced for root.
#' * `stack`: the maximum stack size.
#'
#' @param cur New soft limit, or `NULL` to keep it. `Inf` means unlimited.
#' @param max New hard limit, or `NULL` to keep it.
#' @return A list with elements `cur` and `max`; `Inf` means unlimited.
#'   `rlimit_all()` returns a list of two named numeric vectors, `cur` and
#'   `max`.
#' @references [GETRLIMIT(2)](https://man7.org/linux/man-pages/man2/setrlimit.2.html)
#' @name rlimit
#' @examples
#' rlimit_all()
#' rlimit_nofile()
NULL

rlimit <- function(name, cur, max) {
  if (length(cur)) stopifnot(is.numeric(cur))
  if (length(max)) stopifnot(is.numeric(max))
  lim <- .Call(C_rlimit_get, name)
  if (anyNA(lim)) {
    warning("RLIMIT_", toupper(name), " not available on this system", call. = FALSE)
    return(list(cur = NA_real_, max = NA_real_))
  }
  if (length(cur) || length(max)) {
    new_cur <- if (length(cur)) as.numeric(cur)[1] else lim[[1]]
    new_max <- lim[[2]]
    if (length(cur) && new_cur > new_max) new_max <- new_cur
    if (length(max)) new_max <- as.numeric(max)[1]
    .Call(C_rlimit_set, name, new_cur, new_max)
    lim <- .Call(C_rlimit_get, name)
  }
  list(cur = lim[[1]], max = lim[[2]])
}

#' @rdname rlimit
#' @export
rlimit_all <- function() {
  names <- c("as", "core", "cpu", "data", "fsize", "memlock", "nofile", "nproc", "stack")
  all <- lapply(names, function(n) suppressWarnings(rlimit(n, NULL, NULL)))
  list(cur = structure(vapply(all, `[[`, numeric(1), "cur"), names = names),
       max = structure(vapply(all, `[[`, numeric(1), "max"), names = names))
}

#' @rdname rlimit
#' @export
rlimit_as <- function(cur = NULL, max = NULL) rlimit("as", cur, max)

#' @rdname rlimit
#' @export
rlimit_core <- function(cur = NULL, max = NULL) rlimit("core", cur, max)

#' @rdname rlimit
#' @export
rlimit_cpu <- function(cur = NULL, max = NULL) rlimit("cpu", cur, max)

#' @rdname rlimit
#' @export
rlimit_data <- function(cur = NULL, max = NULL) rlimit("data", cur, max)

#' @rdname rlimit
#' @export
rlimit_fsize <- function(cur = NULL, max = NULL) rlimit("fsize", cur, max)

#' @rdname rlimit
#' @export
rlimit_memlock <- function(cur = NULL, max = NULL) rlimit("memlock", cur, max)

#' @rdname rlimit
#' @export
rlimit_nofile <- function(cur = NULL, max = NULL) rlimit("nofile", cur, max)

#' @rdname rlimit
#' @export
rlimit_nproc <- function(cur = NULL, max = NULL) rlimit("nproc", cur, max)

#' @rdname rlimit
#' @export
rlimit_stack <- function(cur = NULL, max = NULL) rlimit("stack", cur, max)

# eval_safe(rlimits =): the unix semantics. Names must be known resources;
# zero and NA values are ignored; each value sets both limits.
unix_rlimits <- function(rlimits) {
  known <- c("as", "core", "cpu", "data", "fsize", "memlock", "nofile", "nproc", "stack")
  rlimits <- as.list(rlimits)
  nm <- names(rlimits)
  if (is.null(nm) || any(!nzchar(nm)))
    stop("rlimits must be named, for example c(cpu = 60)", call. = FALSE)
  unknown <- setdiff(nm, known)
  if (length(unknown))
    stop("Unsupported rlimits: ", paste(unknown, collapse = ", "), call. = FALSE)
  vals <- vapply(rlimits, function(v) as.numeric(v)[1], numeric(1))
  vals <- vals[!is.na(vals) & vals != 0]
  as.list(vals)
}

#' Change root directory
#'
#' Changes the root directory of the calling process, then its working
#' directory to the new root. Only a privileged process may call it. As the
#' 'unix' package notes, `chroot()` is not a security boundary on its own;
#' combine it with a [policy()].
#'
#' @param path Directory of the new root.
#' @return `path`, normalized.
#' @references [CHROOT(2)](https://man7.org/linux/man-pages/man2/chroot.2.html)
#' @export
chroot <- function(path = getwd()) {
  path <- normalizePath(path, mustWork = TRUE)
  .Call(C_chroot, path)
}

#' Switch user and group
#'
#' Sets the supplementary groups (root only), then the real, effective and
#' saved group id, then the user id, so the process cannot switch back.
#'
#' @param uid,gid User and group as numeric ids or names; `NULL` keeps the
#'   current one.
#' @return `NULL`, invisibly.
#' @export
setids <- function(uid = NULL, gid = NULL) {
  .Call(C_setids, resolve_id(uid, "user"), resolve_id(gid, "group"))
  invisible(NULL)
}
