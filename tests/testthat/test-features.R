# Features from the survey of other sandboxes (.agents/roadmap.md, "parity").

test_that("the child has no controlling terminal", {
  expect_false(eval_fork(.Call(C_test_has_tty)))
  expect_identical(eval_fork(getsid_is_self()), TRUE)
})

test_that("the child dies with the session", {
  skip_if_not(is_linux())
  f <- tempfile("lk-orphan-")
  # A "session" (outer fork) starts a confined child, then dies at once.
  try(eval_fork({
    eval_fork({
      cat(getpid(), file = f)
      Sys.sleep(30)
    }, timeout = 0)
  }, timeout = 1), silent = TRUE)
  for (i in 1:50) if (file.exists(f)) break else Sys.sleep(0.1)
  pid <- as.integer(readLines(f, warn = FALSE))
  for (i in 1:50) if (!process_alive(pid)) break else Sys.sleep(0.1)
  expect_false(process_alive(pid))
})

test_that("die-with-parent is armed, and again after a switch of user", {
  skip_if_not(is_linux())
  sigkill <- tools::SIGKILL
  expect_identical(eval_fork(.Call(C_test_pdeathsig)), sigkill)
  skip_if_not(getuid() == 0L, "needs root")
  # setresuid clears the setting; apply_policy() arms it again.
  pdeath <- function() .Call(C_test_pdeathsig)
  pdeath()
  expect_identical(eval_safe(pdeath(), policy = ids(policy(), uid = 65534)), sigkill)
})

test_that("a timeout grace lets the program clean up", {
  f <- tempfile("lk-grace-")
  expect_error(run("sh", c("-c", sprintf("trap 'echo cleaned > %s; exit 0' TERM; sleep 30 & wait", f)),
                   timeout = 1, grace = 3), "timeout")
  expect_identical(readLines(f, warn = FALSE), "cleaned")
  expect_error(eval_fork(Sys.sleep(30), timeout = 1, grace = 1), "timeout")
})

test_that("run() takes a working directory, umask, environment and stdin", {
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
  expect_error(run("true", stdin = file.path(d, "none")), "does not exist")
})

test_that("stdin is opened before the policy, like a shell redirection", {
  skip_without_landlock()
  input <- tempfile("lk-in-")
  writeLines("hidden", input)
  dirs <- c("/usr/bin", "/bin", "/usr/lib", "/usr/lib64", "/lib", "/lib64")
  p <- fs(landlock_only(), exec = dirs[file.exists(dirs)])
  expect_identical(rawToChar(run("cat", policy = p, stdin = input)$stdout), "hidden\n")
})

test_that("terminal injection ioctls are refused", {
  skip_if_not(is_linux())
  skip_if(is.na(.Call(C_test_tiocsti)), "no TIOCSTI")
  eperm <- -.Call(C_errno_value, "EPERM")
  expect_false(eval_fork(.Call(C_test_tiocsti)) == eperm)
  expect_identical(eval_safe(.Call(C_test_tiocsti), policy = syscalls(policy(), block_tty = TRUE)), eperm)
  expect_match(last_report()$detail, "terminal injection")
  expect_true(preset("numeric")$syscalls$block_tty)
})

test_that("socket families can be limited", {
  skip_if_not(is_linux())
  p <- syscalls(policy(), socket_families = "unix")
  expect_identical(eval_safe(.Call(C_test_socket, .Call(C_af_value, "unix")), policy = p), 0L)
  expect_identical(eval_safe(.Call(C_test_socket, .Call(C_af_value, "inet")), policy = p),
                   -.Call(C_errno_value, "EAFNOSUPPORT"))
  expect_error(syscalls(policy(), socket_families = "carrier-pigeon"))
})

test_that("personality can be locked instead of denied", {
  skip_if_not(is_linux())
  p <- syscalls(policy(), lock_personality = TRUE)
  expect_match(eval_safe({ personality_query(); "ok" }, policy = p), "ok")
  expect_identical(eval_safe(personality_set(0x0040000), policy = p), -.Call(C_errno_value, "EPERM"))
})

test_that("syscall groups make up the dangerous set", {
  groups <- c("debug", "mount", "namespace", "keyring", "module", "reboot", "swap", "clock",
              "privileged", "memory", "kernel", "session", "sandbox")
  expect_setequal(unlist(lapply(groups, preset)), preset("dangerous"))
  expect_true("mount" %in% preset("mount"))
  expect_error(preset("nope"), "groups")
})

test_that("missing paths can be ignored and are reported", {
  skip_without_landlock()
  p <- fs(policy(), read = c(R.home(), "/nonexistent/landlock"), missing = "ignore")
  expect_identical(eval_safe(1, policy = p), 1)
  expect_match(last_report()$detail, "missing, ignored: /nonexistent/landlock")
  expect_error(eval_safe(1, policy = fs(policy(), read = "/nonexistent/landlock")), "does not exist")
})

test_that("older Landlock ABIs report partial enforcement of write rules", {
  skip_without_landlock()
  old <- options(landlock.force_abi = 3L)
  on.exit(options(old))
  eval_safe(1, policy = fs(policy(), rw = tempdir()))
  rep <- last_report()
  expect_identical(rep$status, "partial")
  expect_match(rep$detail, "device ioctl")
  eval_safe(1, policy = fs(policy(), read = tempdir()))
  expect_identical(last_report()$status, "applied")
  expect_error(eval_safe(1, policy = fs(policy(best_effort = FALSE), rw = tempdir())), "cannot enforce")
})

test_that("memory-deny-write-execute refuses writable executable memory", {
  skip_if_not(is_linux())
  expect_identical(eval_fork(.Call(C_test_mmap_wx)), 0L)
  r <- eval_safe(.Call(C_test_mmap_wx), policy = deny_write_execute(policy()))
  if (last_report()$status == "skipped") skip("kernel before 6.3")
  expect_lt(r, 0L)
  expect_identical(eval_safe(sum(1:10), policy = deny_write_execute(policy())), 55L)
})

test_that("further resource limits", {
  skip_if_not(is_linux())
  expect_identical(eval_safe(rlimit_get("rtprio")[["cur"]], policy = limits(policy(), rtprio = 0)), 0)
  expect_identical(eval_safe(rlimit_get("sigpending")[["cur"]], policy = limits(policy(), sigpending = 64)), 64)
  expect_true(preset("numeric")$limits$rtprio == 0)
})

test_that("status() reports errata and the TIOCSTI setting", {
  st <- status()
  expect_true(is.integer(st$landlock_errata))
  expect_true(is.logical(st$tiocsti_legacy))
})
