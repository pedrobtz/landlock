#' What this kernel offers
#'
#' Probes the running system for every confinement layer the package can
#' use. Nothing is changed: the user-namespace probe runs in a short-lived
#' forked child.
#'
#' @return A list of class `lk_status` with elements:
#' \describe{
#'   \item{os, kernel}{Operating system and kernel release.}
#'   \item{landlock_abi}{Landlock ABI version; 0 when Landlock is not
#'     available (older kernel, not built, or disabled at boot).}
#'   \item{landlock_errata}{Bitmask of Landlock fixes the kernel reports
#'     (Linux 6.15 and later), `NA` where the kernel cannot say.}
#'   \item{seccomp, seccomp_filters}{Seccomp mode of this process (0 none,
#'     1 strict, 2 filter) and the number of filters installed.}
#'   \item{no_new_privs}{Whether `no_new_privs` is already set.}
#'   \item{caps}{Capability sets of this process as hexadecimal strings.}
#'   \item{userns}{User namespace limits and whether a child can create one.}
#'   \item{cgroup}{cgroup version, this process's cgroup and whether it is
#'     delegated (writable).}
#'   \item{apparmor}{Whether AppArmor is enabled and the current profile.}
#'   \item{tiocsti_legacy}{Whether the kernel still lets an unprivileged
#'     process push input into a terminal with `TIOCSTI`
#'     (`dev.tty.legacy_tiocsti`); `NA` where the setting does not exist.
#'     Confined children run without a controlling terminal either way.}
#' }
#' Values that do not apply on this system are `NA`.
#' @export
#' @examples
#' status()
status <- function() {
  info <- Sys.info()
  st <- proc_status()
  field <- function(key) if (key %in% names(st)) st[[key]] else NA_character_
  caps <- c(effective = "CapEff", permitted = "CapPrm", inheritable = "CapInh",
            bounding = "CapBnd", ambient = "CapAmb")
  out <- list(
    os = info[["sysname"]],
    kernel = info[["release"]],
    landlock_abi = .Call(C_ll_abi),
    landlock_errata = .Call(C_ll_errata),
    seccomp = suppressWarnings(as.integer(field("Seccomp"))),
    seccomp_filters = suppressWarnings(as.integer(field("Seccomp_filters"))),
    no_new_privs = as.logical(suppressWarnings(as.integer(field("NoNewPrivs")))),
    caps = lapply(as.list(caps), field),
    userns = list(
      max = read_int("/proc/sys/user/max_user_namespaces"),
      unprivileged_clone = read_int("/proc/sys/kernel/unprivileged_userns_clone"),
      apparmor_restricted = read_int("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"),
      works = .Call(C_userns_works)
    ),
    cgroup = cgroup_info(),
    apparmor = apparmor_info(),
    tiocsti_legacy = as.logical(read_int("/proc/sys/dev/tty/legacy_tiocsti"))
  )
  structure(out, class = "lk_status")
}

cgroup_info <- function() {
  root <- "/sys/fs/cgroup"
  version <- if (file.exists(file.path(root, "cgroup.controllers"))) 2L
             else if (dir.exists(root)) 1L else 0L
  path <- NA_character_
  if (file.exists("/proc/self/cgroup")) {
    lines <- tryCatch(readLines("/proc/self/cgroup", warn = FALSE), error = function(e) character())
    v2 <- grep("^0::", lines, value = TRUE)
    if (length(v2)) path <- sub("^0::", "", v2[1])
  }
  delegated <- FALSE
  if (version == 2L && !is.na(path)) {
    dir <- file.path(root, sub("^/", "", path))
    delegated <- dir.exists(dir) &&
      file.access(dir, 2L) == 0L &&
      file.access(file.path(dir, "cgroup.subtree_control"), 2L) == 0L
  }
  list(version = version, path = path, delegated = delegated)
}

apparmor_info <- function() {
  enabled <- identical(read_first_line("/sys/module/apparmor/parameters/enabled"), "Y")
  con <- NA_character_
  mode <- NA_character_
  if (enabled) {
    raw <- read_first_line("/proc/self/attr/apparmor/current")
    if (is.na(raw)) raw <- read_first_line("/proc/self/attr/current")
    if (!is.na(raw)) {
      raw <- sub("\n$", "", raw)
      m <- regmatches(raw, regexec("^(.*) \\(([a-z]+)\\)$", raw))[[1]]
      if (length(m)) {
        con <- m[2]
        mode <- m[3]
      } else {
        con <- raw
      }
    }
  }
  list(enabled = enabled, profile = con, mode = mode)
}

#' @export
print.lk_status <- function(x, ...) {
  yn <- function(v) if (isTRUE(v)) "yes" else if (isFALSE(v)) "no" else "unknown"
  abi <- x$landlock_abi
  cat("<landlock status>", x$os, x$kernel, "\n")
  cat("  Landlock      ", if (abi > 0) paste("ABI", abi) else "not available", "\n")
  cat("  seccomp       ", if (is.na(x$seccomp)) "unknown" else c("none", "strict", "filter")[x$seccomp + 1L],
      if (!is.na(x$seccomp_filters) && x$seccomp_filters > 0) paste0("(", x$seccomp_filters, " filters)"), "\n")
  cat("  no_new_privs  ", yn(x$no_new_privs), "\n")
  cat("  capabilities  ", if (is.na(x$caps$effective)) "unknown"
      else if (grepl("^0+$", x$caps$effective)) "none effective"
      else paste("effective", x$caps$effective), "\n")
  cat("  user ns       ", yn(x$userns$works), "\n")
  cat("  cgroup        ", if (x$cgroup$version == 0L) "none" else paste0("v", x$cgroup$version),
      if (isTRUE(x$cgroup$delegated)) "(delegated)", "\n")
  if (!is.na(x$tiocsti_legacy))
    cat("  TIOCSTI       ", if (x$tiocsti_legacy) "allowed (legacy)" else "restricted", "\n")
  cat("  AppArmor      ", if (isTRUE(x$apparmor$enabled))
      paste0("enabled, profile ", x$apparmor$profile,
             if (!is.na(x$apparmor$mode)) paste0(" (", x$apparmor$mode, ")")) else "not enabled", "\n")
  invisible(x)
}
