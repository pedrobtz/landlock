#' @rdname sys_config
#' @export
aa_config <- function() {
  linux <- is_linux()
  info <- apparmor_info()
  list(
    compiled = linux,
    enabled = if (linux) info$enabled else NULL,
    con = if (!is.na(info$profile)) info$profile else NULL,
    mode = if (!is.na(info$mode)) info$mode else NULL
  )
}

#' Change AppArmor profile
#'
#' Asks AppArmor to move the calling process into another profile, by
#' writing to `/proc/self/attr/apparmor/current` as 'libapparmor' does. The
#' profile must be loaded and must allow the change. Irreversible unless
#' the target profile allows changing back.
#'
#' @param profile Name of the profile.
#' @return `NULL`, invisibly.
#' @examples
#' # Needs AppArmor and a loaded profile; irreversible, so in a child.
#' if (isTRUE(aa_config()$enabled)) {
#'   try(eval_fork(aa_change_profile("unconfined")))
#' }
#' @export
aa_change_profile <- function(profile) {
  stopifnot(is.character(profile), length(profile) == 1L)
  if (!isTRUE(apparmor_info()$enabled))
    stop("AppArmor is not enabled on this system", call. = FALSE)
  .Call(C_aa_change_profile, profile)
  invisible(NULL)
}
