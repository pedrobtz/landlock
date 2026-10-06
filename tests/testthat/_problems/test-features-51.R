# Extracted from test-features.R:51

# setup ------------------------------------------------------------------------
library(testthat)
test_env <- simulate_test_env(package = "landlock", path = "..")
attach(test_env, warn.conflicts = FALSE)

# test -------------------------------------------------------------------------
d <- tempfile("lk-wd-")
dir.create(d)
expect_identical(rawToChar(run("pwd", wd = d)$stdout), paste0(normalizePath(d), "\n"))
expect_identical(trimws(rawToChar(run("sh", c("-c", "umask"), umask = "027")$stdout)), "0027")
Sys.setenv(LK_SESSION_VAR = "visible")
on.exit(Sys.unsetenv("LK_SESSION_VAR"))
expect_identical(rawToChar(run("sh", c("-c", "printf %s \"$LK_SESSION_VAR\""))$stdout), "visible")
expect_identical(rawToChar(run("/bin/sh", c("-c", "printf %s \"$LK_SESSION_VAR$LK_X\""),
                                 clear_env = TRUE, env = c(LK_X = "only"))$stdout), "only")
input <- tempfile("lk-in-")
writeLines(c("b", "a"), input)
expect_identical(rawToChar(run("sort", stdin = input)$stdout), "a\nb\n")
