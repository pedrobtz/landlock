#' Apply a policy
#'
#' `apply_policy()` is the engine behind [eval_safe()], [run()] and
#' [confine()]: it applies the layers of a [policy()] to the calling process,
#' in a fixed order: AppArmor, Landlock, the capability bounding set,
#' seccomp, user and group ids, the remaining capability sets, resource
#' limits. Each step needs what the later ones take away. It is irreversible; call it in a child process,
#' or use `confine()`, which adds a check for threads.
#'
#' `confine()` applies a policy to the current R session. Landlock restricts
#' only the calling thread and the threads and processes it creates later,
#' so `confine()` refuses to run in a session that already has other threads
#' (a multi-threaded BLAS, for example) unless `force = TRUE`.
#'
#' @param p A [policy()].
#' @param strict If `TRUE`, fail when the kernel cannot provide a requested
#'   layer instead of skipping it. Defaults to the policy's `best_effort`
#'   setting.
#' @return A report of class `lk_report`: a data frame with one row per
#'   requested layer and the columns `layer`, `status` (`"applied"`,
#'   `"partial"` when the kernel's Landlock ABI cannot enforce every right a
#'   write rule asks for, or `"skipped"`) and `detail`. Strict mode fails
#'   instead of applying a partial or skipped layer. Returned invisibly; also available as
#'   [last_report()].
#' @examples
#' # Irreversible, so shown in a throwaway child:
#' eval_fork({
#'   confine(limits(policy(), cpu = 60))
#'   rlimit_cpu()$cur
#' })
#'
#' eval_fork(apply_policy(limits(policy(), cpu = 60)))
#' @export
apply_policy <- function(p, strict = !isTRUE(p$best_effort)) {
  check_policy(p)
  rows <- list()
  add <- function(layer, status, detail) {
    rows[[length(rows) + 1L]] <<- data.frame(layer = layer, status = status, detail = detail,
                                              stringsAsFactors = FALSE)
  }
  abi <- .Call(C_ll_abi)

  # AppArmor (between steps 6 and 7)
  if (!is.null(p$apparmor)) {
    if (isTRUE(apparmor_info()$enabled)) {
      aa_change_profile(p$apparmor)
      add("apparmor", "applied", paste("profile", p$apparmor))
    } else if (strict) {
      stop("AppArmor is not enabled; cannot change to profile '", p$apparmor, "'", call. = FALSE)
    } else {
      add("apparmor", "skipped", "AppArmor is not enabled")
    }
  }

  # Landlock (step 7)
  want_fs <- !is.null(p$fs) || isTRUE(p$fs_tmp)
  want_net <- !is.null(p$net)
  want_scope <- !is.null(p$scope) && (p$scope$signal || p$scope$abstract_unix)
  if (want_fs || want_net || want_scope) {
    fsr <- p$fs
    if (isTRUE(p$fs_tmp)) {
      scratch <- .state$child_tmp %||% tempdir()
      fsr <- rbind(fsr, data.frame(path = scratch, mode = fs_modes[["read"]] + fs_modes[["write"]],
                                   stringsAsFactors = FALSE))
    }
    rules <- landlock_rules(fsr, missing_ok = identical(p$fs_missing, "ignore"))
    ignored <- attr(rules, "missing")
    kernel_abi <- if (abi > 0L) min(abi, if (force_abi() > 0L) force_abi() else abi) else abi
    gaps <- if (want_fs && kernel_abi > 0L) unenforced_rights(kernel_abi, rules$mode) else character()
    if (length(gaps) && strict)
      stop("Landlock ABI ", kernel_abi, " cannot enforce: ", paste(gaps, collapse = ", "),
           ", and strict mode is on", call. = FALSE)
    log <- if (is.null(p$log)) 0L else if (isTRUE(p$log)) 2L else 1L
    flags <- c(want_fs, want_net, want_scope && p$scope$signal, want_scope && p$scope$abstract_unix,
               log, !strict, force_abi())
    r <- .Call(C_ll_restrict, rules$path, rules$mode,
               p$net$bind %||% integer(), p$net$connect %||% integer(), as.integer(flags))
    used <- r[[1]]
    abi <- used  # the report header shows the ABI the rules were written for
    none <- if (used == 0L) "Landlock is not available on this kernel" else NULL
    if (want_fs) {
      detail <- none %||% sprintf("ABI %d, %d rule%s", used, nrow(rules), if (nrow(rules) == 1L) "" else "s")
      if (r[[2]] && length(gaps)) detail <- paste0(detail, "; not enforced at this ABI: ", paste(gaps, collapse = ", "))
      if (length(ignored)) detail <- paste0(detail, "; missing, ignored: ", paste(ignored, collapse = ", "))
      add("landlock-fs", if (!r[[2]]) "skipped" else if (length(gaps)) "partial" else "applied", detail)
    }
    if (want_net)
      add("landlock-net", if (r[[3]]) "applied" else "skipped",
          none %||% if (r[[3]]) sprintf("TCP bind: %s; connect: %s", ports_text(p$net$bind), ports_text(p$net$connect))
          else sprintf("TCP rules need Landlock ABI 4; the kernel offers %d", used))
    if (want_scope)
      add("landlock-scope", if (r[[4]]) "applied" else "skipped",
          none %||% if (r[[4]]) paste(c("signal", "abstract_unix")[c(p$scope$signal, p$scope$abstract_unix)], collapse = ", ")
          else sprintf("scopes need Landlock ABI 6; the kernel offers %d", used))
  }

  # Capability bounding set (step 8): needs CAP_SETPCAP, so before the
  # sets are cleared and before seccomp could deny prctl variants.
  caps_nr <- NULL
  caps_bounding <- FALSE
  if (!is.null(p$caps)) {
    if (is_linux()) {
      caps_nr <- cap_numbers(p$caps$keep)
      caps_bounding <- drop_bounding(caps_nr)
    } else if (strict) {
      stop("capabilities are only available on Linux", call. = FALSE)
    }
  }

  # Memory-deny-write-execute (prctl; before seccomp, which may restrict prctl).
  if (isTRUE(p$mdwe)) {
    rc <- if (is_linux()) .Call(C_mdwe_set) else -1L
    if (rc == 0L) {
      add("memory", "applied", "no writable and executable mappings")
    } else if (strict) {
      stop("memory-deny-write-execute is not available (needs Linux 6.3)", call. = FALSE)
    } else {
      add("memory", "skipped", "memory-deny-write-execute needs Linux 6.3")
    }
  }

  # seccomp (step 10): last of the one-way filters, so it can deny what the
  # earlier steps used (landlock_*, unshare, mount).
  if (!is.null(p$syscalls)) {
    res <- install_filter(p$syscalls, strict = strict)
    add("seccomp", res$status, res$detail)
  }

  # User and group ids (step 11): after seccomp, whose presets never deny
  # set*id; before the capability sets are cleared, which removes
  # CAP_SETUID.
  if (!is.null(p$ids) && !(is.na(p$ids$uid) && is.na(p$ids$gid))) {
    .Call(C_setids, p$ids$uid, p$ids$gid)
    # A credential change clears die-with-parent: arm it again.
    .Call(C_rearm_pdeathsig)
    add("ids", "applied", sprintf("uid %s, gid %s", p$ids$uid, p$ids$gid))
  }

  # Capability sets and no_new_privs (step 12).
  if (!is.null(p$caps)) {
    if (!is.null(caps_nr)) {
      clear_caps(caps_nr)
      add("caps", "applied", caps_detail(p$caps$keep, caps_bounding))
    } else {
      add("caps", "skipped", "capabilities are only available on Linux")
    }
  }

  # Resource limits (step 12): ceilings, never raised above the hard limit.
  # A limit the platform does not have, or refuses (macOS rejects an
  # address-space limit), is skipped and named in the report; in strict mode
  # it is an error.
  if (length(p$limits)) {
    shown <- character()
    refused <- character()
    for (name in names(p$limits)) {
      want <- p$limits[[name]]
      if (!is.numeric(want) || length(want) != 1L || is.na(want) || want < 0)
        stop("limits(): invalid value for ", name, call. = FALSE)
      cur <- .Call(C_rlimit_get, name)
      why <- NULL
      if (anyNA(cur)) {
        why <- "not available on this system"
      } else {
        v <- min(want, cur[[2]])
        why <- tryCatch({
          .Call(C_rlimit_set, name, v, v)
          NULL
        }, error = function(e) sub("^setrlimit\\(\\): ", "", conditionMessage(e)))
      }
      if (is.null(why)) {
        shown <- c(shown, paste0(name, "=", if (is.finite(v)) format(v, scientific = FALSE) else "unlimited"))
      } else if (strict) {
        stop("limits(): cannot set ", name, ": ", why, call. = FALSE)
      } else {
        refused <- c(refused, paste0(name, " (", why, ")"))
      }
    }
    if (length(shown))
      add("limits", "applied", paste(c(shown, if (length(refused)) paste("not set:", paste(refused, collapse = ", "))),
                                     collapse = ", "))
    else
      add("limits", "skipped", paste("not set:", paste(refused, collapse = ", ")))
  }

  report <- if (length(rows)) do.call(rbind, rows)
            else data.frame(layer = character(), status = character(), detail = character(),
                            stringsAsFactors = FALSE)
  report <- structure(report, landlock_abi = abi, class = c("lk_report", "data.frame"))
  .state$last_report <- report
  invisible(report)
}

# Testing hook: pretend the kernel offers at most this Landlock ABI (or,
# with -1, none). Anything but a whole number from -1 to 7 is ignored.
force_abi <- function() {
  v <- getOption("landlock.force_abi")
  if (is.null(v)) return(0L)
  ok <- is.numeric(v) && length(v) == 1L && !is.na(v) && v == round(v) && v >= -1 && v <= 7
  if (!ok) {
    warning("ignoring invalid option landlock.force_abi", call. = FALSE)
    return(0L)
  }
  as.integer(v)
}

ports_text <- function(v) if (length(v)) paste(v, collapse = ", ") else "none"

# One rule per existing path, modes merged; paths must exist.
landlock_rules <- function(fs, missing_ok = FALSE) {
  if (is.null(fs) || !nrow(fs)) return(data.frame(path = character(), mode = integer()))
  missing <- fs$path[!file.exists(fs$path)]
  if (length(missing) && !missing_ok)
    stop("fs(): path does not exist: ", paste(unique(missing), collapse = ", "), call. = FALSE)
  fs <- fs[file.exists(fs$path), , drop = FALSE]
  if (!nrow(fs)) return(structure(data.frame(path = character(), mode = integer()),
                                  missing = unique(missing)))
  path <- normalizePath(fs$path, mustWork = TRUE)
  mode <- tapply(fs$mode, path, function(m) Reduce(bitwOr, m))
  structure(data.frame(path = names(mode), mode = as.integer(mode), stringsAsFactors = FALSE),
            missing = unique(missing))
}

# Rights a write rule asks for that an older Landlock ABI cannot enforce
# (design.md section 9): what "partial" means in the report.
unenforced_rights <- function(abi, modes) {
  if (!any(bitwAnd(modes, fs_modes[["write"]]) != 0L)) return(character())
  need <- c("rename and link across directories" = 2L, truncate = 3L, "device ioctl" = 5L)
  names(need)[abi < need]
}

#' @rdname apply_policy
#' @param force Apply even if the session has more than one thread.
#' @export
confine <- function(p, force = FALSE, strict = !isTRUE(p$best_effort)) {
  check_policy(p)
  n <- thread_count()
  if (n > 1L && !isTRUE(force))
    stop("confine(): this R session runs ", n, " threads, and Landlock restricts only the ",
         "calling thread. Use eval_safe() to confine a child process, or force = TRUE.",
         call. = FALSE)
  apply_policy(p, strict = strict)
}

thread_count <- function() {
  if (!dir.exists("/proc/self/task")) return(1L)
  length(list.files("/proc/self/task"))
}

#' The report of the last enforcement
#'
#' Every [eval_safe()], [run()], [confine()] and [apply_policy()] call that
#' was given a policy records which layers it applied and which it skipped.
#'
#' @return The most recent report (class `lk_report`), or `NULL` if no policy
#'   has been applied in this session.
#' @examples
#' eval_safe(sum(1:10), policy = preset("numeric"))
#' last_report()
#' @export
last_report <- function() {
  .state$last_report
}

#' @export
print.lk_report <- function(x, ...) {
  abi <- attr(x, "landlock_abi")
  cat("<landlock report>", if (!is.null(abi)) paste("Landlock ABI", abi), "\n")
  if (!nrow(x)) {
    cat("  no layers requested\n")
    return(invisible(x))
  }
  for (i in seq_len(nrow(x)))
    cat(sprintf("  %-15s %-8s %s\n", x$layer[i], x$status[i], x$detail[i]))
  invisible(x)
}
