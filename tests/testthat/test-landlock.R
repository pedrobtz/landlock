test_that("the numeric preset denies reading outside its paths", {
  skip_without_landlock()
  msg <- eval_safe(tryCatch(readLines("/etc/passwd"), warning = conditionMessage),
                   policy = preset("numeric"))
  expect_match(msg, "Permission denied")
  expect_identical(last_report()$status[last_report()$layer == "landlock-fs"], "applied")
})

test_that("the numeric preset lets R compute", {
  skip_without_landlock()
  fit <- eval_safe(coef(lm(mpg ~ wt, data = mtcars)), policy = preset("numeric"))
  expect_equal(fit, coef(lm(mpg ~ wt, data = mtcars)))
})

test_that("writes are confined to the allowed hierarchy", {
  skip_without_landlock()
  # the call's own scratch directory (TMPDIR) is writable; tempdir() is not
  expect_identical(eval_safe({
    f <- file.path(Sys.getenv("TMPDIR"), "x")
    writeLines("x", f)
    readLines(f)
  }, policy = preset("numeric")), "x")
  outside <- file.path(dirname(tempdir()), paste0("landlock-denied-", Sys.getpid()))
  expect_false(eval_safe(suppressWarnings(file.create(outside)), policy = preset("numeric")))
  expect_false(file.exists(outside))
})

test_that("execution needs the loader too", {
  skip_without_landlock()
  p <- fs(landlock_only(), exec = c("/usr/bin", "/bin")[file.exists(c("/usr/bin", "/bin"))])
  expect_error(run("true", policy = p), "Permission denied")
})

test_that("nothing can be executed under the numeric preset", {
  skip_without_landlock()
  expect_error(eval_safe(system("true", intern = TRUE), policy = preset("numeric")))
  expect_error(run("true", policy = landlock_only()), "Permission denied")
  # with the preset's seccomp filter, execve itself is refused first
  expect_error(run("true", policy = preset("numeric")), "Operation not permitted")
})

test_that("run() works when execution is allowed", {
  skip_without_landlock()
  # The kernel opens the dynamic loader for execution too.
  dirs <- c("/usr/bin", "/bin", "/usr/lib", "/usr/lib64", "/lib", "/lib64")
  p <- fs(landlock_only(), exec = dirs[file.exists(dirs)])
  f <- tempfile()
  writeLines("inside", f)
  expect_identical(rawToChar(run("cat", f, policy = fs(p, read = f))$stdout), "inside\n")
  r <- run("cat", "/etc/passwd", policy = p)
  expect_false(r$status == 0L)
  expect_match(rawToChar(r$stderr), "Permission denied")
})

test_that("inherited descriptors are closed under a policy", {
  skip_without_landlock()
  fd <- .Call(C_test_open_fd, "/etc/passwd")
  on.exit(.Call(C_test_close_fd, fd))
  expect_gt(eval_fork(.Call(C_test_read_fd, fd)), 0L)
  expect_identical(eval_safe(.Call(C_test_read_fd, fd), policy = preset("numeric")), 0L)  # /dev/null
})

test_that("TCP bind and connect follow the allow-lists", {
  skip_without_landlock(4L)
  p <- net(policy(), bind = 47631)
  expect_error(eval_safe(serverSocket(47632), policy = p))
  expect_true(eval_safe({
    s <- serverSocket(47631)
    close(s)
    TRUE
  }, policy = p))
})

test_that("scope() keeps signals inside the sandbox", {
  skip_without_landlock(6L)
  expect_error(eval_safe(kill(getppid(), 0L), policy = scope(policy())), "Operation not permitted")
  expect_null(eval_safe(kill(getpid(), 0L), policy = scope(policy())))
})

test_that("best effort skips what the kernel lacks; strict fails", {
  old <- options(landlock.force_abi = -1L)
  on.exit(options(old))
  p <- fs(policy(), read = "/")
  eval_safe(1, policy = p)
  expect_identical(last_report()$status, "skipped")
  expect_error(eval_safe(1, policy = fs(policy(best_effort = FALSE), read = "/")), "lacks")
})

test_that("TCP rules are skipped below ABI 4", {
  skip_without_landlock(4L)
  old <- options(landlock.force_abi = 3L)
  on.exit(options(old))
  eval_safe(1, policy = net(policy()))
  rep <- last_report()
  expect_identical(rep$status, "skipped")
  expect_match(rep$detail, "ABI 4")
})

test_that("restrict_self() confines a child", {
  skip_without_landlock()
  msg <- eval_fork({
    restrict_self(read = R.home())
    tryCatch(readLines("/etc/passwd"), warning = conditionMessage)
  })
  expect_match(msg, "Permission denied")
})

test_that("a missing AppArmor is reported, not fatal", {
  skip_if(isTRUE(aa_config()$enabled))
  eval_safe(1, policy = apparmor(policy(), "landlock-test"))
  expect_identical(last_report()$status, "skipped")
})
