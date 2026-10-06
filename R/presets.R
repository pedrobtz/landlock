#' Ready-made policies
#'
#' Policies for common cases, built for the running session when called
#' (they read [R.home()], [.libPaths()] and [tempdir()]). Start from one and
#' add to it with the [policy()] verbs.
#'
#' * `"numeric"`: evaluate R code that only computes. Reads R, the
#'   installed packages and system libraries; writes only the session's
#'   temporary directory; may execute nothing; no TCP; signals and abstract
#'   sockets scoped to the sandbox.
#' * `"install"`: install a package from source. As `"numeric"`, plus
#'   executing the compiler toolchain and writing to `lib`.
#' * `"plumber"`: serve HTTP. As `"numeric"`, plus binding to `port`.
#'
#' Paths that do not exist on this system are left out.
#'
#' @param name Name of the preset.
#' @param ... Arguments of the preset: `lib` for `"install"` (default the
#'   first library path), `port` for `"plumber"` (default 8000).
#' @return A [policy()].
#' @export
#' @examples
#' preset("numeric")
preset <- function(name, ...) {
  stopifnot(is.character(name), length(name) == 1L)
  switch(name,
    numeric = preset_numeric(),
    install = preset_install(...),
    plumber = preset_plumber(...),
    stop("unknown preset '", name, "'; available: numeric, install, plumber", call. = FALSE)
  )
}

existing <- function(x) unique(x[nzchar(x) & file.exists(x)])

r_read_paths <- function() {
  existing(c(R.home(), .libPaths(), "/usr", "/lib", "/lib64", "/opt/R",
             "/etc/R", "/etc/ld.so.cache", "/etc/localtime", "/etc/timezone",
             "/etc/os-release", "/dev/urandom", "/dev/null"))
}

preset_numeric <- function() {
  p <- fs(policy(), read = r_read_paths(), write = existing(c(tempdir(), "/dev/null")))
  p <- net(p)
  scope(p)
}

preset_install <- function(lib = .libPaths()[1]) {
  stopifnot(is.character(lib), length(lib) == 1L)
  p <- preset_numeric()
  fs(p, read = existing(c("/etc", "/bin", "/sbin")),
     exec = existing(c(R.home(), "/usr/bin", "/bin", "/usr/lib", "/usr/libexec",
                       "/usr/local/bin", "/opt/R")),
     write = lib)
}

preset_plumber <- function(port = 8000) {
  net(preset_numeric(), bind = port)
}
