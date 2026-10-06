test_that("syscalls() validates names everywhere", {
  p <- syscalls(policy(), deny = c("getppid", "open"))
  expect_identical(p$syscalls$deny, c("getppid", "open"))
  expect_identical(p$syscalls$action, "errno")
  expect_identical(syscalls(p, deny = "ptrace")$syscalls$deny, c("getppid", "open", "ptrace"))
  expect_error(syscalls(policy(), deny = "not_a_syscall"), "unknown system call")
  expect_error(syscalls(policy(), deny = "getppid", errno = "EWHAT"), "errno")
  expect_error(syscalls(policy(), deny = "getppid", action = "explode"))
})

test_that("syscall presets only name known calls", {
  for (set in c("dangerous", "no_exec", "no_net"))
    expect_true(all(preset(set) %in% syscall_names), label = set)
  expect_false(any(c("setuid", "setresuid", "setgroups", "capset", "prctl") %in% preset("dangerous")))
})

test_that("the errno action makes a call fail", {
  skip_if_not(is_linux())
  expect_identical(eval_safe(getppid(), policy = syscalls(policy(), deny = "getppid")), -1L)
  rep <- last_report()
  expect_identical(rep$layer, "seccomp")
  expect_identical(rep$status, "applied")
  expect_match(rep$detail, "deny 1 call")
  expect_identical(eval_safe(seccomp_status()$mode, policy = syscalls(policy(), deny = "getppid")), 2L)
})

test_that("the kill action kills the child", {
  skip_if_not(is_linux())
  p <- syscalls(policy(), deny = "getppid", action = "kill")
  expect_error(eval_safe(getppid(), policy = p), "child process has died")
})

test_that("no_exec stops system()", {
  skip_if_not(is_linux())
  p <- syscalls(policy(), deny = preset("no_exec"))
  # The command must not run. How the refused execve surfaces depends on how
  # the C library spawns: an error when posix_spawn reports it (glibc), a
  # warning about exit status 127 when it is fork then exec (valgrind).
  outcome <- eval_safe(tryCatch(system("true", intern = TRUE),
                                error = function(e) "refused", warning = function(w) "refused"),
                       policy = p)
  expect_identical(outcome, "refused")
  expect_identical(eval_safe(sum(1:4), policy = p), 10L)
})

test_that("the dangerous set leaves ordinary R working", {
  skip_if_not(is_linux())
  p <- syscalls(policy(), deny = preset("dangerous"))
  fit <- eval_safe(coef(lm(mpg ~ wt, data = mtcars)), policy = p)
  expect_equal(fit, coef(lm(mpg ~ wt, data = mtcars)))
  expect_identical(eval_fork(eval_fork(1 + 1)), 2)
})

test_that("seccomp_deny() works on the calling process", {
  skip_if_not(is_linux())
  # getppid() "cannot fail", so C libraries return the raw result: -1
  # (glibc on x86_64) or -errno (glibc on i386, musl). Either way, < 0.
  r <- eval_fork({
    seccomp_deny("getppid", errno = "EACCES")
    getppid()
  })
  expect_true(r %in% c(-1L, -13L))
})

test_that("syscall_table() lists this architecture's calls", {
  t <- syscall_table()
  expect_named(t, c("name", "nr"))
  if (is_linux()) {
    expect_gt(nrow(t), 150L)
    expect_true("getppid" %in% t$name)
  } else {
    expect_identical(nrow(t), 0L)
  }
})

test_that("seccomp is skipped off Linux, or an error in strict mode", {
  skip_if(is_linux())
  eval_safe(1, policy = syscalls(policy(), deny = "getppid"))
  expect_identical(last_report()$status, "skipped")
  expect_error(eval_safe(1, policy = syscalls(policy(best_effort = FALSE), deny = "getppid")),
               "only available on Linux")
  expect_error(seccomp_deny("getppid"), "only available on Linux")
})

test_that("caps() clears the capability sets", {
  skip_if_not(is_linux())
  out <- eval_safe(status()[c("caps", "no_new_privs")], policy = caps(policy()))
  expect_match(out$caps$effective, "^0+$")
  expect_match(out$caps$permitted, "^0+$")
  expect_match(out$caps$ambient, "^0+$")
  expect_true(out$no_new_privs)
  rep <- last_report()
  expect_identical(rep$layer, "caps")
  expect_identical(rep$status, "applied")
})

test_that("caps() empties the bounding set when privileged", {
  skip_if_not(is_linux())
  skip_if(grepl("^0+$", status()$caps$effective), "no capabilities to drop")
  bnd <- eval_safe(status()$caps$bounding, policy = caps(policy()))
  expect_match(bnd, "^0+$")
  expect_match(last_report()$detail, "bounding set emptied")
})

test_that("root can still switch user after caps() and seccomp", {
  # Also covers a child that cannot read the package library once it is
  # nobody: everything it runs afterwards must already be in memory.
  skip_if_not(is_linux())
  skip_if_not(getuid() == 0L, "needs root")
  p <- ids(caps(syscalls(policy(), deny = preset("dangerous"))), uid = 65534, gid = 65534)
  # Under R CMD check the package is installed in root's 0700 temporary
  # directory, which nobody cannot read: load what the child will use first.
  ids_now <- function() c(getuid(), geteuid(), getgid())
  ids_now()
  expect_identical(eval_safe(ids_now(), policy = p), rep(65534L, 3))
})

test_that("caps() validates names", {
  expect_error(caps(policy(), keep = "flying"), "unknown capability")
  expect_identical(caps(policy(), keep = "CAP_NET_BIND_SERVICE")$caps$keep, "CAP_NET_BIND_SERVICE")
})

test_that("the numeric preset applies every layer it can", {
  skip_without_landlock(6L)
  expect_identical(eval_safe(sum(1:10), policy = preset("numeric")), 55L)
  rep <- last_report()
  expect_setequal(rep$layer, c("landlock-fs", "landlock-net", "landlock-scope", "seccomp", "caps",
                               "limits"))
  expect_true(all(rep$status == "applied"))
})
