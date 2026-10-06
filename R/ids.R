#' User and group information
#'
#' Look up a user or a group by id or name, with the same results as the
#' 'unix' package.
#'
#' @param uid User id (integer) or name (string).
#' @param gid Group id (integer) or name (string).
#' @return `user_info()`: a list with `name`, `passwd`, `uid`, `gid`,
#'   `gecos`, `dir` and `shell`. `group_info()`: a list with `name`,
#'   `passwd`, `gid` and `members`.
#' @references [GETPWNAM(3)](https://man7.org/linux/man-pages/man3/getpwnam.3.html)
#'   [GETGRNAM(3)](https://man7.org/linux/man-pages/man3/getgrnam.3.html)
#' @name userinfo
#' @examples
#' user_info()
#' group_info()
NULL

#' @rdname userinfo
#' @export
user_info <- function(uid = getuid()) {
  if (is.numeric(uid)) uid <- as.integer(uid)
  stopifnot(length(uid) > 0, is.numeric(uid) || is.character(uid))
  out <- .Call(C_user_info, uid)
  structure(out, names = c("name", "passwd", "uid", "gid", "gecos", "dir", "shell"))
}

#' @rdname userinfo
#' @export
group_info <- function(gid = getgid()) {
  if (is.numeric(gid)) gid <- as.integer(gid)
  stopifnot(length(gid) > 0, is.integer(gid) || is.character(gid))
  out <- .Call(C_group_info, gid)
  structure(out, names = c("name", "passwd", "gid", "members"))
}
