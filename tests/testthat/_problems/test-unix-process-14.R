# Extracted from test-unix-process.R:14

# setup ------------------------------------------------------------------------
library(testthat)
test_env <- simulate_test_env(package = "landlock", path = "..")
attach(test_env, warn.conflicts = FALSE)

# test -------------------------------------------------------------------------
expect_type(getuid(), "integer")
expect_type(getgid(), "integer")
expect_type(getpriority(), "integer")
expect_true(eval_fork({
    setpgid()
    getpid() == getpgid()
  }))
