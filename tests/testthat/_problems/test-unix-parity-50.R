# Extracted from test-unix-parity.R:50

# setup ------------------------------------------------------------------------
library(testthat)
test_env <- simulate_test_env(package = "landlock", path = "..")
attach(test_env, warn.conflicts = FALSE)

# prequel ----------------------------------------------------------------------
unix_formals <- list(
  aa_config = alist(),
  chroot = alist(path = getwd()),
  eval_fork = alist(expr = , tmp = tempfile("fork"), std_out = stdout(), std_err = stderr(),
                    timeout = 0),
  eval_safe = alist(expr = , tmp = tempfile("fork"), std_out = stdout(), std_err = stderr(),
                    timeout = 0, priority = NULL, uid = NULL, gid = NULL, rlimits = NULL,
                    profile = NULL, device = pdf),
  getegid = alist(), geteuid = alist(), getgid = alist(), getpgid = alist(),
  getpid = alist(), getppid = alist(), getpriority = alist(), getuid = alist(),
  group_info = alist(gid = getgid()),
  kill = alist(pid = , signal = SIGTERM),
  rlimit_all = alist(),
  rlimit_as = alist(cur = NULL, max = NULL), rlimit_core = alist(cur = NULL, max = NULL),
  rlimit_cpu = alist(cur = NULL, max = NULL), rlimit_data = alist(cur = NULL, max = NULL),
  rlimit_fsize = alist(cur = NULL, max = NULL), rlimit_memlock = alist(cur = NULL, max = NULL),
  rlimit_nofile = alist(cur = NULL, max = NULL), rlimit_nproc = alist(cur = NULL, max = NULL),
  rlimit_stack = alist(cur = NULL, max = NULL),
  setegid = alist(gid = ), seteuid = alist(uid = ), setgid = alist(gid = ),
  setpgid = alist(pgid = 0), setpriority = alist(prio = ), setuid = alist(uid = ),
  sys_config = alist(),
  user_info = alist(uid = getuid())
)
deparsed <- function(args) {
  vapply(args, function(a) paste(deparse(a), collapse = " "), character(1))
}

# test -------------------------------------------------------------------------
extra <- setdiff(names(formals(eval_safe)), names(unix_formals$eval_safe))
expect_identical(extra, "policy")
