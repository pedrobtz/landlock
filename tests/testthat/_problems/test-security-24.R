# Extracted from test-security.R:24

# setup ------------------------------------------------------------------------
library(testthat)
test_env <- simulate_test_env(package = "landlock", path = "..")
attach(test_env, warn.conflicts = FALSE)

# test -------------------------------------------------------------------------
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
p <- limits(policy(), nofile = 512)
expect_error(eval_safe(forge(evil_env()), policy = p), "malformed result")
expect_false(file.exists(marker))
trap <- list(ok = TRUE, value = 1, visible = TRUE, report = evil_env())
expect_identical(eval_safe(forge(trap), policy = p), 1)
expect_false(file.exists(marker))
expect_null(last_report())
