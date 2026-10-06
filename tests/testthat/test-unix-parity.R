# The 'unix' 1.6.0 API (design.md section 15): every export exists with the
# same formals, in the same order, with the same defaults. landlock may add
# trailing arguments (eval_safe() adds `policy`).

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

test_that("every unix export is exported", {
  expect_length(unix_formals, 32L)
  missing <- setdiff(names(unix_formals), getNamespaceExports("landlock"))
  expect_identical(missing, character())
})

test_that("unix formals are kept, in order, with the same defaults", {
  for (name in names(unix_formals)) {
    ours <- as.list(formals(get(name, envir = asNamespace("landlock"))))
    ref <- unix_formals[[name]]
    expect_identical(names(ours)[seq_along(ref)], names(ref), label = name)
    expect_identical(deparsed(ours[seq_along(ref)]), deparsed(ref), label = name)
  }
})

test_that("additions are trailing and defaulted", {
  extra <- setdiff(names(formals(eval_safe)), names(unix_formals$eval_safe))
  expect_identical(extra, "policy")
  expect_null(formals(eval_safe)$policy)
})

test_that("results have the unix shapes", {
  expect_named(rlimit_nofile(), c("cur", "max"))
  expect_named(rlimit_all(), c("cur", "max"))
  expect_named(rlimit_all()$cur, c("as", "core", "cpu", "data", "fsize", "memlock",
                                   "nofile", "nproc", "stack"))
  expect_named(user_info(), c("name", "passwd", "uid", "gid", "gecos", "dir", "shell"))
  expect_named(group_info(), c("name", "passwd", "gid", "members"))
  expect_named(sys_config(), c("safe", "apparmor"))
  expect_named(aa_config(), c("compiled", "enabled", "con", "mode"))
  expect_identical(user_info(getuid())$uid, getuid())
  expect_identical(user_info(user_info()$name)$uid, getuid())
})
