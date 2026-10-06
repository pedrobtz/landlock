test_that("verbs build a plain list", {
  p <- policy() |>
    fs(read = "/usr", write = tempdir(), rw = "/dev/null") |>
    net(bind = 8080) |>
    net(connect = c(443, 443)) |>
    scope(abstract_unix = FALSE) |>
    limits(memory = "1g", nofile = 256, cpu = 30) |>
    apparmor("unconfined")
  expect_s3_class(p, "lk_policy")
  expect_identical(p$fs$path, c("/usr", tempdir(), "/dev/null"))
  expect_identical(p$fs$mode, c(1L, 2L, 3L))
  expect_identical(p$net, list(bind = 8080L, connect = 443L))
  expect_identical(p$scope, list(signal = TRUE, abstract_unix = FALSE))
  expect_identical(p$limits$as, 1024^3)
  expect_identical(p$limits$nofile, 256)
  expect_identical(p$apparmor, "unconfined")
  expect_output(print(p), "landlock policy")
})

test_that("fs() with no paths denies everything", {
  p <- fs(policy())
  expect_identical(nrow(p$fs), 0L)
})

test_that("bad input is rejected when the policy is built", {
  expect_error(fs(policy(), read = 1), "character")
  expect_error(net(policy(), bind = 70000), "65535")
  expect_error(net(policy(), connect = 1.5), "integers")
  expect_error(limits(policy(), memory = "lots"), "cannot read size")
  expect_error(limits(policy(), memory = -1), "non-negative")
  expect_error(fs(list()), "policy\\(\\)")
  expect_error(policy(best_effort = NA))
})

test_that("sizes parse with 1024-based suffixes", {
  expect_identical(parse_size("512k", "x"), 512 * 1024)
  expect_identical(parse_size("64M", "x"), 64 * 1024^2)
  expect_identical(parse_size("2g", "x"), 2 * 1024^3)
  expect_identical(parse_size(100, "x"), 100)
})

test_that("ids() resolves names", {
  me <- user_info()
  p <- ids(policy(), uid = me$name, gid = group_info()$name)
  expect_identical(p$ids, list(uid = getuid(), gid = getgid()))
})

test_that("presets exist and only list existing paths", {
  for (name in c("numeric", "install", "plumber")) {
    p <- preset(name)
    expect_s3_class(p, "lk_policy")
    expect_true(all(file.exists(p$fs$path)))
  }
  expect_identical(preset("plumber", port = 9000)$net$bind, 9000L)
  expect_error(preset("nope"), "unknown preset")
})

test_that("paths are checked when applied, not when built", {
  p <- fs(policy(), read = "/nonexistent/landlock")
  expect_s3_class(p, "lk_policy")
  expect_error(eval_safe(1, policy = p), "does not exist")
})
