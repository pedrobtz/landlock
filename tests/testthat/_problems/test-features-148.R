# Extracted from test-features.R:148

# setup ------------------------------------------------------------------------
library(testthat)
test_env <- simulate_test_env(package = "landlock", path = "..")
attach(test_env, warn.conflicts = FALSE)

# test -------------------------------------------------------------------------
expect_identical(eval_safe(format(Sys.umask()), policy = umask(policy(), "027")), "27")
expect_identical(last_report()$layer, "umask")
expect_error(umask(policy(), "999"), "octal")
