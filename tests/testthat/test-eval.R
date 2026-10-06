test_that("visibility is kept", {
  expect_false(withVisible(eval_safe(invisible(1)))$visible)
  expect_true(withVisible(eval_safe(1))$visible)
})

test_that("the child is reaped after a timeout", {
  pid <- NULL
  elapsed <- system.time(
    expect_error(eval_fork({
      cat(Sys.getpid(), file = file.path(tempdir(), "lk-child-pid"))
      Sys.sleep(30)
    }, timeout = 1), "timeout")
  )[["elapsed"]]
  expect_lt(elapsed, if (under_gctorture()) 60 else 10)
  pid <- as.integer(readLines(file.path(tempdir(), "lk-child-pid"), warn = FALSE))
  expect_error(kill(pid, 0L), "No such process")
})

test_that("a normal child is reaped too", {
  pid <- eval_fork(getpid())
  expect_error(kill(pid, 0L), "No such process")
})

test_that("a mebibyte of output does not deadlock", {
  con <- rawConnection(raw(0), "r+")
  on.exit(close(con))
  eval_fork(cat(strrep("a", 2^20)), std_out = con)
  expect_equal(length(rawConnectionValue(con)), 2^20)
})

test_that("output goes to files and can be discarded", {
  f <- tempfile()
  eval_fork(cat("to a file"), std_out = f)
  expect_identical(readLines(f, warn = FALSE), "to a file")
  expect_silent(eval_fork(cat("gone"), std_out = FALSE))
})

test_that("limits apply and are ceilings", {
  skip_if(under_valgrind(), "valgrind refuses to change RLIMIT_NOFILE")
  expect_identical(eval_safe(rlimit_nofile()$cur, policy = limits(policy(), nofile = 100)), 100)
  rep <- last_report()
  expect_s3_class(rep, "lk_report")
  expect_identical(rep$layer, "limits")
  expect_identical(rep$status, "applied")
  hard <- rlimit_nofile()$max
  if (is.finite(hard))
    expect_identical(eval_safe(rlimit_nofile()$max, policy = limits(policy(), nofile = hard * 2)), hard)
})

test_that("run() executes a program", {
  r <- run("echo", c("hello", "world"))
  expect_identical(r$status, 0L)
  expect_identical(rawToChar(r$stdout), "hello world\n")
  expect_identical(run("sh", c("-c", "exit 3"))$status, 3L)
  expect_identical(rawToChar(run("sh", c("-c", "printf %s \"$LK_X\""), env = c(LK_X = "y"))$stdout), "y")
  expect_error(run("landlock-no-such-program"), "cannot run")
  expect_null(run("echo", "x", std_out = FALSE)$stdout)
})

test_that("run() reports a program killed by a signal", {
  r <- run("sh", c("-c", "kill -9 $$"))
  expect_true(is.na(r$status))
  expect_identical(r$signal, 9L)
})

test_that("confine() refuses a multi-threaded session", {
  local_mocked_bindings(thread_count = function() 3L)
  expect_error(confine(policy()), "threads")
})

test_that("confine() and apply_policy() work in a child", {
  skip_if(under_valgrind(), "valgrind refuses to change RLIMIT_NOFILE")
  expect_identical(eval_fork({
    confine(limits(policy(), nofile = 99))
    rlimit_nofile()$cur
  }), 99)
})

test_that("inherited descriptors stay open without a policy", {
  fd <- .Call(C_test_open_fd, scratch_file())
  on.exit(.Call(C_test_close_fd, fd))
  expect_gt(eval_fork(.Call(C_test_read_fd, fd)), 0L)
})

test_that("a limit the platform refuses is reported, or an error in strict mode", {
  skip_if(under_asan(), "an address-space limit breaks ASan, which reserves terabytes")
  # macOS rejects an address-space limit; Linux accepts it.
  res <- eval_safe(1, policy = limits(policy(), memory = "64g", core = 0))
  expect_identical(res, 1)
  rep <- last_report()
  expect_identical(rep$layer, "limits")
  if (!is_linux()) {
    expect_match(rep$detail, "not set: as")
    expect_error(eval_safe(1, policy = limits(policy(best_effort = FALSE), memory = "64g")),
                 "cannot set as")
  } else {
    expect_identical(rep$status, "applied")
  }
})
