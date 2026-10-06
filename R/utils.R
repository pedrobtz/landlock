`%||%` <- function(x, y) if (is.null(x)) y else x

is_linux <- function() {
  identical(Sys.info()[["sysname"]], "Linux")
}

read_first_line <- function(path) {
  if (!file.exists(path)) return(NA_character_)
  out <- tryCatch(readLines(path, n = 1L, warn = FALSE), error = function(e) character())
  if (length(out)) out else NA_character_
}

read_int <- function(path) {
  suppressWarnings(as.integer(read_first_line(path)))
}

# "Key:\tvalue" lines of /proc/self/status as a named character vector.
proc_status <- function() {
  path <- "/proc/self/status"
  if (!file.exists(path)) return(character())
  lines <- tryCatch(readLines(path, warn = FALSE), error = function(e) character())
  key <- sub(":.*$", "", lines)
  val <- trimws(sub("^[^:]*:", "", lines))
  structure(val, names = key)
}

# 1024-based sizes: 1e6, "100k", "64m", "1g", "2t".
parse_size <- function(x, what) {
  if (is.null(x)) return(NULL)
  if (is.numeric(x)) {
    if (length(x) != 1L || is.na(x) || x < 0) stop(what, " must be a single non-negative number")
    return(as.double(x))
  }
  if (!is.character(x) || length(x) != 1L) stop(what, " must be a number or a size such as \"512m\"")
  m <- regmatches(x, regexec("^\\s*([0-9.]+)\\s*([kKmMgGtT]?)[bB]?\\s*$", x))[[1]]
  if (!length(m)) stop(what, ": cannot read size \"", x, "\"")
  mult <- c(" " = 1, k = 1024, m = 1024^2, g = 1024^3, t = 1024^4)[[if (nzchar(m[3])) tolower(m[3]) else " "]]
  v <- suppressWarnings(as.double(m[2])) * mult
  if (is.na(v)) stop(what, ": cannot read size \"", x, "\"")
  v
}

format_size <- function(x) {
  if (!is.finite(x)) return("unlimited")
  units <- c("B", "KiB", "MiB", "GiB", "TiB")
  i <- 1L
  while (x >= 1024 && i < length(units) && x %% 1024 == 0) {
    x <- x / 1024
    i <- i + 1L
  }
  paste0(format(x, scientific = FALSE), if (i > 1L) " ", if (i > 1L) units[i] else "")
}

strsignal <- function(sig) .Call(C_strsignal, as.integer(sig))
