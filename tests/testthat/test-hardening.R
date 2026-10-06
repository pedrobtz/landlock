# Every way out of eval_fork() / run() must leave no child behind
# (roadmap Stage 5). Each case records the child's pid in a file first.

pid_file <- function() tempfile("lk-pid-")

child_gone <- function(pid) {
  identical(tryCatch(kill(pid, 0L), error = function(e) "gone"), "gone")
}

test_that("an interrupt kills and reaps the child, and is a real interrupt", {
  skip_on_os("windows")
  f <- pid_file()
  # The "session" is itself a fork, so the test process is never signalled.
  out <- eval_fork({
    me <- getpid()
    system(sprintf("(sleep 1; kill -INT %d) >/dev/null 2>&1 &", me))
    t0 <- Sys.time()
    caught <- tryCatch(
      eval_fork({
        cat(getpid(), file = f)
        Sys.sleep(30)
      }),
      interrupt = function(e) "interrupt"
    )
    list(caught = caught, elapsed = as.numeric(Sys.time() - t0, units = "secs"))
  }, timeout = 60)
  expect_identical(out$caught, "interrupt")
  expect_lt(out$elapsed, if (under_gctorture()) 60 else 10)
  expect_true(child_gone(as.integer(readLines(f, warn = FALSE))))
})

test_that("an error in an output callback kills and reaps the child", {
  f <- pid_file()
  expect_error(
    eval_fork({
      cat(getpid(), file = f)
      cat("first chunk\n")
      Sys.sleep(30)
    }, std_out = function(x) stop("callback failed")),
    "callback failed"
  )
  expect_true(child_gone(as.integer(readLines(f, warn = FALSE))))
})

test_that("grandchildren in the child's process group are killed too", {
  f <- pid_file()
  expect_error(eval_fork({
    system(sprintf("sleep 30 & echo $! > %s; wait", f))
  }, timeout = 1), "timeout")
  Sys.sleep(0.2)
  expect_true(child_gone(as.integer(readLines(f, warn = FALSE))))
})

test_that("run() reaps on timeout", {
  f <- pid_file()
  expect_error(run("sh", c("-c", sprintf("echo $$ > %s; sleep 30", f)), timeout = 1), "timeout")
  expect_true(child_gone(as.integer(readLines(f, warn = FALSE))))
})

test_that("many forks leave no descriptors behind", {
  skip_if_not(dir.exists("/proc/self/fd"))
  before <- length(list.files("/proc/self/fd"))
  for (i in seq_len(if (under_gctorture()) 3 else 50)) eval_fork(i)
  for (i in seq_len(if (under_gctorture()) 2 else 20)) run("true")
  expect_identical(length(list.files("/proc/self/fd")), before)
})

test_that("under a policy inherited descriptors point at /dev/null", {
  skip_if_not(dir.exists("/proc/self/fd"))
  f <- scratch_file()
  fd <- .Call(C_test_open_fd, f)
  on.exit(.Call(C_test_close_fd, fd))
  target <- eval_safe(Sys.readlink(sprintf("/proc/self/fd/%d", fd)),
                      policy = limits(policy(), core = 0))
  expect_identical(target, "/dev/null")
  expect_identical(eval_fork(Sys.readlink(sprintf("/proc/self/fd/%d", fd))),
                   normalizePath(f))
})

test_that("a session graphics device cannot leak into the child's output", {
  f <- tempfile(fileext = ".pdf")
  grDevices::pdf(f)
  on.exit(grDevices::dev.off())
  con <- rawConnection(raw(0), "r+")
  on.exit(close(con), add = TRUE)
  eval_safe(1, std_out = con, policy = limits(policy(), core = 0))
  expect_identical(rawConnectionValue(con), raw(0))
})

test_that("binary output to a text connection does not fail", {
  out <- character()
  tc <- textConnection("out", "w", local = TRUE)
  run("sh", c("-c", "printf 'A\\000B'"), std_out = tc)
  close(tc)
  expect_identical(out, "AB")
})

test_that("a policy error in the child is an error in the session", {
  expect_error(eval_safe(1, policy = fs(policy(), read = "/nonexistent/landlock")),
               "does not exist")
  expect_error(run("true", policy = fs(policy(), read = "/nonexistent/landlock")),
               "does not exist")
})
