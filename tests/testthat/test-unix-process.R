# Adapted from the 'unix' package, tests/testthat/test-process.R
# (https://github.com/jeroen/unix), MIT licence, Copyright (c) 2017 Jeroen Ooms.
# Full notice: inst/COPYRIGHTS. Changes: expect_is() replaced for testthat 3e;
# setpgid() runs in a fork so the test session keeps its process group.

test_that("process stuff", {
  expect_type(getuid(), "integer")
  expect_type(getgid(), "integer")
  expect_type(getpriority(), "integer")

  expect_true(eval_fork({
    setpgid()
    getpid() == getpgid()
  }))
})
