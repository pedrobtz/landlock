# The gctorture CI leg sets gctorture2() in the session; forked children
# inherit it. Fork-heavy tests do less under it.
under_gctorture <- function() {
  step <- gctorture2(0)
  gctorture2(step)
  step > 0
}

landlock_abi <- function() .Call(C_ll_abi)

skip_without_landlock <- function(abi = 1L) {
  have <- landlock_abi()
  skip_if(have < abi, sprintf("needs Landlock ABI %d, kernel offers %d", abi, have))
}

errmsg <- function(expr) tryCatch({ expr; "" }, error = conditionMessage)
