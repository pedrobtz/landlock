#' Capabilities and no_new_privs
#'
#' `caps_drop_all()` empties the capability bounding set (so nothing can
#' regain a capability, which needs `CAP_SETPCAP` and so only works for a
#' privileged process), clears the effective, permitted, inheritable and
#' ambient sets, and sets `no_new_privs`. `caps_keep()` does the same but
#' keeps the named capabilities. Irreversible. Linux only.
#'
#' `no_new_privs()` sets the `no_new_privs` flag: neither the process nor
#' its children can gain privileges through `execve()` (set-user-id
#' programs, file capabilities). Landlock and seccomp set it as well.
#'
#' @param ... Capability names, with or without the `CAP_` prefix, in any
#'   case: `"net_bind_service"`, `"CAP_SYS_CHROOT"`.
#' @return `caps_drop_all()` and `caps_keep()`: `TRUE` if the bounding set
#'   was emptied, `FALSE` if the process lacked the privilege to do so,
#'   invisibly. `no_new_privs()`: `TRUE`, invisibly.
#' @export
caps_drop_all <- function() {
  invisible(drop_caps(character(), strict = TRUE)$bounding)
}

#' @rdname caps_drop_all
#' @export
caps_keep <- function(...) {
  invisible(drop_caps(c(...), strict = TRUE)$bounding)
}

#' @rdname caps_drop_all
#' @export
no_new_privs <- function() {
  if (!is_linux()) stop("no_new_privs is only available on Linux", call. = FALSE)
  invisible(.Call(C_nnp_set))
}

cap_names <- c(
  "chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill", "setgid",
  "setuid", "setpcap", "linux_immutable", "net_bind_service", "net_broadcast",
  "net_admin", "net_raw", "ipc_lock", "ipc_owner", "sys_module", "sys_rawio",
  "sys_chroot", "sys_ptrace", "sys_pacct", "sys_admin", "sys_boot", "sys_nice",
  "sys_resource", "sys_time", "sys_tty_config", "mknod", "lease", "audit_write",
  "audit_control", "setfcap", "mac_override", "mac_admin", "syslog", "wake_alarm",
  "block_suspend", "audit_read", "perfmon", "bpf", "checkpoint_restore"
)

cap_numbers <- function(keep) {
  if (!length(keep)) return(integer())
  if (!is.character(keep) || anyNA(keep)) stop("capabilities must be given as names", call. = FALSE)
  key <- sub("^cap_", "", tolower(keep))
  nr <- match(key, cap_names) - 1L
  if (anyNA(nr)) stop("unknown capability: ", paste(keep[is.na(nr)], collapse = ", "), call. = FALSE)
  nr
}

# The two halves of the capability layer (design.md section 4: the
# bounding set before seccomp, the sets after the id switch).
drop_bounding <- function(keep_nr) {
  rc <- .Call(C_caps_drop_bounding, keep_nr)
  if (rc == 0L) return(TRUE)
  if (rc == -.Call(C_errno_value, "EPERM")) return(FALSE)
  stop("dropping the capability bounding set: ", .Call(C_strerror, rc), call. = FALSE)
}

clear_caps <- function(keep_nr) {
  rc <- .Call(C_caps_clear, keep_nr)
  if (rc != 0L) stop("clearing capabilities: ", .Call(C_strerror, rc), call. = FALSE)
  .Call(C_nnp_set)
  invisible(TRUE)
}

drop_caps <- function(keep, strict) {
  if (!is_linux()) {
    if (strict) stop("capabilities are only available on Linux", call. = FALSE)
    return(list(status = "skipped", bounding = FALSE))
  }
  nr <- cap_numbers(keep)
  bounding <- drop_bounding(nr)
  clear_caps(nr)
  list(status = "applied", bounding = bounding)
}

caps_detail <- function(keep, bounding) {
  paste0(if (bounding) "bounding set emptied" else "bounding set kept (needs CAP_SETPCAP)",
         "; effective, permitted, inheritable and ambient cleared",
         if (length(keep)) paste0("; kept: ", paste(keep, collapse = ", ")) else "")
}
