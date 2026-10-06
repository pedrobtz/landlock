/* Routine registration for every C_* entry point in the R glue files.
 * Keep in sync when adding one. */
#define R_NO_REMAP
#include <R.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>

SEXP C_ll_abi(void);
SEXP C_ll_restrict(SEXP paths, SEXP modes, SEXP bind, SEXP connect, SEXP flags);
SEXP C_sc_table(void);
SEXP C_sc_lookup(SEXP names);
SEXP C_sc_install(SEXP nrs, SEXP actions, SEXP errnums, SEXP deny_clone_ns);
SEXP C_sc_status(void);
SEXP C_errno_value(SEXP name);
SEXP C_cap_last(void);
SEXP C_caps_drop_bounding(SEXP keep);
SEXP C_caps_clear(SEXP keep);
SEXP C_nnp_set(void);
SEXP C_nnp_get(void);
SEXP C_strerror(SEXP err);
SEXP C_rlimit_get(SEXP name);
SEXP C_rlimit_set(SEXP name, SEXP cur, SEXP max);
SEXP C_getid(SEXP which);
SEXP C_setid(SEXP which, SEXP id);
SEXP C_setids(SEXP uid, SEXP gid);
SEXP C_getpid(void);
SEXP C_getppid(void);
SEXP C_getpgid(void);
SEXP C_setpgid(SEXP pgid);
SEXP C_getpriority(void);
SEXP C_setpriority(SEXP prio);
SEXP C_kill(SEXP pid, SEXP sig);
SEXP C_chroot(SEXP path);
SEXP C_aa_change_profile(SEXP profile);
SEXP C_userns_works(void);
SEXP C_user_info(SEXP input);
SEXP C_group_info(SEXP input);
SEXP C_fork_eval(SEXP fun, SEXP timeout, SEXP outfun, SEXP errfun, SEXP close_fds,
                 SEXP max_result);
SEXP C_child_abort(void);
SEXP C_write_frame(SEXP type, SEXP data);
SEXP C_exec(SEXP cmd, SEXP args);
SEXP C_strsignal(SEXP sig);
SEXP C_test_open_fd(SEXP path);
SEXP C_test_read_fd(SEXP fd);
SEXP C_test_close_fd(SEXP fd);
SEXP C_test_clone_newuser(void);
SEXP C_test_clone3_errno(void);
SEXP C_freeze(SEXP interrupt);

static const R_CallMethodDef call_methods[] = {
    {"C_ll_abi", (DL_FUNC) &C_ll_abi, 0},
    {"C_ll_restrict", (DL_FUNC) &C_ll_restrict, 5},
    {"C_sc_table", (DL_FUNC) &C_sc_table, 0},
    {"C_sc_lookup", (DL_FUNC) &C_sc_lookup, 1},
    {"C_sc_install", (DL_FUNC) &C_sc_install, 4},
    {"C_sc_status", (DL_FUNC) &C_sc_status, 0},
    {"C_errno_value", (DL_FUNC) &C_errno_value, 1},
    {"C_cap_last", (DL_FUNC) &C_cap_last, 0},
    {"C_caps_drop_bounding", (DL_FUNC) &C_caps_drop_bounding, 1},
    {"C_caps_clear", (DL_FUNC) &C_caps_clear, 1},
    {"C_nnp_set", (DL_FUNC) &C_nnp_set, 0},
    {"C_nnp_get", (DL_FUNC) &C_nnp_get, 0},
    {"C_strerror", (DL_FUNC) &C_strerror, 1},
    {"C_rlimit_get", (DL_FUNC) &C_rlimit_get, 1},
    {"C_rlimit_set", (DL_FUNC) &C_rlimit_set, 3},
    {"C_getid", (DL_FUNC) &C_getid, 1},
    {"C_setid", (DL_FUNC) &C_setid, 2},
    {"C_setids", (DL_FUNC) &C_setids, 2},
    {"C_getpid", (DL_FUNC) &C_getpid, 0},
    {"C_getppid", (DL_FUNC) &C_getppid, 0},
    {"C_getpgid", (DL_FUNC) &C_getpgid, 0},
    {"C_setpgid", (DL_FUNC) &C_setpgid, 1},
    {"C_getpriority", (DL_FUNC) &C_getpriority, 0},
    {"C_setpriority", (DL_FUNC) &C_setpriority, 1},
    {"C_kill", (DL_FUNC) &C_kill, 2},
    {"C_chroot", (DL_FUNC) &C_chroot, 1},
    {"C_aa_change_profile", (DL_FUNC) &C_aa_change_profile, 1},
    {"C_userns_works", (DL_FUNC) &C_userns_works, 0},
    {"C_user_info", (DL_FUNC) &C_user_info, 1},
    {"C_group_info", (DL_FUNC) &C_group_info, 1},
    {"C_fork_eval", (DL_FUNC) &C_fork_eval, 6},
    {"C_child_abort", (DL_FUNC) &C_child_abort, 0},
    {"C_write_frame", (DL_FUNC) &C_write_frame, 2},
    {"C_exec", (DL_FUNC) &C_exec, 2},
    {"C_strsignal", (DL_FUNC) &C_strsignal, 1},
    {"C_test_open_fd", (DL_FUNC) &C_test_open_fd, 1},
    {"C_test_read_fd", (DL_FUNC) &C_test_read_fd, 1},
    {"C_test_close_fd", (DL_FUNC) &C_test_close_fd, 1},
    {"C_test_clone_newuser", (DL_FUNC) &C_test_clone_newuser, 0},
    {"C_test_clone3_errno", (DL_FUNC) &C_test_clone3_errno, 0},
    {"C_freeze", (DL_FUNC) &C_freeze, 1},
    {NULL, NULL, 0}
};

void R_init_landlock(DllInfo *dll)
{
    R_registerRoutines(dll, NULL, call_methods, NULL, NULL);
    R_useDynamicSymbols(dll, FALSE);
    R_forceSymbols(dll, TRUE);
}
