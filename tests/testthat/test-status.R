test_that("status() has the documented shape", {
  st <- status()
  expect_s3_class(st, "lk_status")
  expect_named(st, c("os", "kernel", "landlock_abi", "landlock_errata", "seccomp",
                     "seccomp_filters", "no_new_privs", "caps", "userns", "cgroup", "apparmor",
                     "tiocsti_legacy"))
  expect_type(st$landlock_abi, "integer")
  expect_gte(st$landlock_abi, 0L)
  expect_named(st$caps, c("effective", "permitted", "inheritable", "bounding", "ambient"))
  expect_named(st$userns, c("max", "unprivileged_clone", "apparmor_restricted", "works"))
  expect_named(st$cgroup, c("version", "path", "delegated"))
  expect_named(st$apparmor, c("enabled", "profile", "mode"))
  expect_output(print(st), "landlock status")
})

test_that("status() on Linux reads /proc", {
  skip_if_not(is_linux())
  st <- status()
  expect_true(st$seccomp %in% 0:2)
  expect_type(st$no_new_privs, "logical")
  expect_match(st$caps$bounding, "^[0-9a-f]+$")
})

test_that("status() elsewhere reports absence", {
  skip_if(is_linux())
  st <- status()
  expect_identical(st$landlock_abi, 0L)
  expect_false(st$userns$works)
})
