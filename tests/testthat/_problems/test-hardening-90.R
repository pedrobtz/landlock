# Extracted from test-hardening.R:90

# setup ------------------------------------------------------------------------
library(testthat)
test_env <- simulate_test_env(package = "landlock", path = "..")
attach(test_env, warn.conflicts = FALSE)

# prequel ----------------------------------------------------------------------
pid_file <- function() tempfile("lk-pid-")
child_gone <- function(pid) {
  identical(tryCatch(kill(pid, 0L), error = function(e) "gone"), "gone")
}

# test -------------------------------------------------------------------------
expect_silent(eval_fork(writeBin(as.raw(c(65, 0, 66)), stdout()), std_out = textConnection("x", "w", local = TRUE)))
