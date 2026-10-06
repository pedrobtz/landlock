# Adapted from the 'unix' package, tests/testthat/test-process.R
# (https://github.com/jeroen/unix), MIT licence, Copyright (c) 2017 Jeroen Ooms.
# Full notice: inst/COPYRIGHTS. Change: expect_is() replaced for testthat 3e.
# setpgid() runs in the test process, as upstream: forked children run in a
# session of their own, and a session leader cannot change its group.

test_that("process stuff", {
  expect_type(getuid(), "integer")
  expect_type(getgid(), "integer")
  expect_type(getpriority(), "integer")

  setpgid()
  expect_equal(getpid(), getpgid())
})
