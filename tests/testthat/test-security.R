# Regression tests for the Stage 5 security review (.agents/security.md).

test_that("a forged result frame cannot run code in the session", {
  marker <- tempfile("lk-pwned-")
  forge <- function(payload) {
    # What confined code can do: write its own frame before the real one.
    .Call(C_write_frame, "P", serialize(payload, NULL))
    "honest"
  }
  evil_env <- function() {
    e <- new.env()
    makeActiveBinding("ok", function() { file.create(marker); TRUE }, e)
    makeActiveBinding("report", function() { file.create(marker); NULL }, e)
    e
  }
  p <- limits(policy(), core = 0)
  expect_error(eval_safe(forge(evil_env()), policy = p), "malformed result")
  expect_false(file.exists(marker))

  # a list whose fields are traps
  trap <- list(ok = TRUE, value = 1, visible = TRUE, report = evil_env())
  before <- last_report()
  expect_identical(eval_safe(forge(trap), policy = p), 1)
  expect_false(file.exists(marker))
  expect_identical(last_report(), before)  # the trap was dropped, not stored
})

test_that("a forged error is rebuilt from plain fields", {
  p <- limits(policy(), core = 0)
  err <- tryCatch(eval_safe({
    e <- new.env()
    makeActiveBinding("message", function() stop("ran in the session"), e)
    .Call(C_write_frame, "P", serialize(list(ok = FALSE, error = e), NULL))
    1
  }, policy = p), error = identity)
  expect_s3_class(err, "error")
  expect_match(conditionMessage(err), "unreadable error")
})

test_that("errors from confined code keep message and class", {
  err <- tryCatch(eval_safe(stop(structure(class = c("my_error", "error", "condition"),
                                           list(message = "boom", call = NULL))),
                            policy = limits(policy(), core = 0)),
                  error = identity)
  expect_s3_class(err, "my_error")
  expect_identical(conditionMessage(err), "boom")
})

test_that("the result size is capped", {
  old <- options(landlock.max_result = 1e5)
  on.exit(options(old))
  expect_error(eval_fork(raw(1e6)), "larger than")
  expect_identical(length(eval_fork(raw(1e3))), 1000L)
})

test_that("the default scratch directory is private to the call and removed", {
  tmp <- eval_fork(Sys.getenv("TMPDIR"))
  expect_false(dir.exists(tmp))
  mine <- tempfile("keep")
  expect_identical(eval_fork(Sys.getenv("TMPDIR"), tmp = mine), normalizePath(mine))
  expect_true(dir.exists(mine))
})

test_that("presets grant the scratch directory, not the session's tempdir", {
  skip_without_landlock()
  p <- preset("numeric")
  expect_true(p$fs_tmp)
  expect_false(tempdir() %in% p$fs$path)
  expect_identical(eval_safe({
    f <- file.path(Sys.getenv("TMPDIR"), "x")
    writeLines("in scratch", f)
    readLines(f)
  }, policy = p), "in scratch")
  planted <- file.path(tempdir(), "lk-planted")
  expect_false(eval_safe(suppressWarnings(file.create(planted)), policy = p))
  expect_false(file.exists(planted))
})

test_that("ids are validated and a uid brings its group", {
  expect_error(ids(policy(), uid = -1), "whole number")
  expect_error(ids(policy(), uid = 4e9), "whole number")
  expect_error(ids(policy(), uid = NA), "single id")
  me <- user_info()
  expect_identical(ids(policy(), uid = me$uid)$ids, list(uid = me$uid, gid = me$gid))
})

test_that("root switching user drops its groups", {
  skip_if_not(getuid() == 0L, "needs root")
  out <- run("id", c("-G"), policy = ids(policy(), uid = 65534))
  expect_identical(trimws(rawToChar(out$stdout)), as.character(user_info(65534)$gid))
})

test_that("sizes that do not parse are rejected", {
  expect_error(limits(policy(), memory = "1.5.g"), "cannot read size")
  expect_error(limits(policy(), memory = NA_real_), "non-negative")
})

test_that("an invalid testing option is ignored", {
  old <- options(landlock.force_abi = "off")
  on.exit(options(old))
  expect_warning(force_abi(), "ignoring")
})

test_that("denying unshare also refuses namespaces through clone", {
  skip_if_not(is_linux())
  skip_if(is.na(.Call(C_test_clone_newuser)), "clone() test not available on this architecture")
  p <- syscalls(policy(), deny = "unshare")
  expect_identical(eval_safe(.Call(C_test_clone_newuser), policy = p), -1L)  # EPERM
  expect_match(last_report()$detail, "namespace flags refused")
  # ordinary process creation still works under the filter
  expect_identical(eval_safe(eval_fork(1 + 1), policy = p), 2)
})

test_that("clone3 fails with ENOSYS so the C library falls back", {
  skip_if_not(is_linux())
  skip_if(is.na(.Call(C_test_clone3_errno)), "no clone3 on this architecture")
  p <- syscalls(policy(), deny = "clone3")
  expect_identical(eval_safe(.Call(C_test_clone3_errno), policy = p),
                   .Call(C_errno_value, "ENOSYS"))
  expect_identical(eval_safe(eval_fork(2 + 2), policy = p), 4)
})

test_that("the dangerous set covers the review's gaps", {
  d <- preset("dangerous")
  expect_true(all(c("clone3", "pidfd_getfd", "setsid", "setpgid", "unshare") %in% d))
  expect_true("socketcall" %in% preset("no_net"))
})
