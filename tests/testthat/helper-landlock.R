# The gctorture CI leg sets gctorture2() in the session; forked children
# inherit it. Fork-heavy tests do less under it.
under_gctorture <- function() {
  step <- gctorture2(0)
  gctorture2(step)
  step > 0
}

# Valgrind emulates setrlimit(RLIMIT_NOFILE) and refuses to change the hard
# limit (it reserves descriptors for itself), so tests that lower nofile
# cannot run under it.
under_valgrind <- function() {
  maps <- "/proc/self/maps"
  file.exists(maps) && any(grepl("vgpreload", readLines(maps, warn = FALSE), fixed = TRUE))
}

landlock_abi <- function() .Call(C_ll_abi)

skip_without_landlock <- function(abi = 1L) {
  have <- landlock_abi()
  skip_if(have < abi, sprintf("needs Landlock ABI %d, kernel offers %d", abi, have))
}

errmsg <- function(expr) tryCatch({ expr; "" }, error = conditionMessage)

# The numeric preset's Landlock layers alone, without its seccomp filter
# (which denies execve, so exec fails with EPERM before Landlock decides)
# and without dropping capabilities.
landlock_only <- function() {
  p <- preset("numeric")
  p$syscalls <- NULL
  p$caps <- NULL
  p
}

# A readable file the tests own (R.home()/COPYING is absent on Alpine).
scratch_file <- function() {
  f <- tempfile("lk-file-")
  writeLines("landlock test file", f)
  f
}

# AddressSanitizer reserves terabytes of address space, so an address-space
# limit (limits(memory =)) makes its own allocations fail.
under_asan <- function() {
  maps <- "/proc/self/maps"
  file.exists(maps) && any(grepl("libasan|libclang_rt\\.asan", readLines(maps, warn = FALSE)))
}

getsid_is_self <- function() {
  stat <- "/proc/self/stat"
  if (!file.exists(stat)) return(TRUE)  # macOS: covered by the C harness
  f <- strsplit(sub("^.*\\) ", "", readLines(stat, warn = FALSE)), " ")[[1]]
  identical(as.integer(f[4]), Sys.getpid())  # field 6 of stat, the session id
}

process_alive <- function(pid) {
  if (identical(tryCatch(kill(pid, 0L), error = function(e) "gone"), "gone")) return(FALSE)
  stat <- sprintf("/proc/%d/stat", pid)
  if (!file.exists(stat)) return(TRUE)
  f <- strsplit(sub("^.*\\) ", "", readLines(stat, warn = FALSE)), " ")[[1]]
  !identical(f[1], "Z")
}

rlimit_get <- function(name) {
  v <- .Call(C_rlimit_get, name)
  c(cur = v[[1]], max = v[[2]])
}

personality_query <- function() .Call(C_test_personality, 0xffffffff)
personality_set <- function(value) .Call(C_test_personality, value)
