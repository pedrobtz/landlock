#' Evaluate in a forked, optionally confined, child process
#'
#' `eval_fork()` evaluates an expression in a temporary fork of the R session
#' and returns its value, without side effects on the session. `eval_safe()`
#' adds error handling, graphics isolation, resource limits, user switching,
#' an AppArmor profile and, through `policy`, every layer of a [policy()].
#' Both keep the arguments of the 'unix' package functions of the same name,
#' in the same order; `policy` is added at the end.
#'
#' The child is killed when `timeout` seconds of wall-clock time pass, when
#' the session is interrupted, and when the session itself dies (so a killed
#' R process leaves no sandboxed child running without its timeout). It
#' runs in a session of its own, with no controlling terminal, so it cannot
#' inject input into the user's terminal. Errors in the child are raised again in
#' the session with their original class. Output the child writes is
#' forwarded as it arrives.
#'
#' Some software is not fork-safe and cannot be used in the child once the
#' session has loaded it (Java, and on macOS anything built on
#' CoreFoundation, including a `libcurl` built against SecureTransport). The
#' same holds for [parallel::mcparallel()].
#'
#' @section Output streams:
#' `std_out` and `std_err` may be `TRUE` (the session's [stdout()] and
#' [stderr()]), `FALSE` or `NULL` (discard), a file name, a connection, or a
#' function of one argument that receives each chunk as a raw vector.
#'
#' @section Differences from 'unix':
#' The 'unix' package switches [tempdir()] and [interactive()] inside the
#' child by writing to R internals, which a package on CRAN may not do. Here
#' `tmp` becomes the child's `TMPDIR` (seen by [Sys.getenv()], child
#' processes and C libraries) while [tempdir()] keeps the session's value,
#' and [interactive()] keeps the session's value; standard input is
#' `/dev/null`. Output is captured with [sink()], which also works under
#' front-ends such as RStudio.
#'
#' @param expr Expression to evaluate.
#' @param tmp Temporary directory for the child; becomes its `TMPDIR`. When
#'   left at its default it is created for the call and removed afterwards.
#' @param std_out,std_err Where the child's output goes; see *Output streams*.
#' @param timeout Wall-clock limit in seconds; `0` for none.
#' @param grace Seconds between `SIGTERM` and `SIGKILL` when the timeout
#'   passes; `0` (the default) kills at once.
#' @param priority Scheduling priority of the child; see [setpriority()].
#' @param uid,gid User and group to switch to (root only), as ids or names.
#'   A `uid` without a `gid` takes the user's primary group, and the
#'   supplementary groups are replaced, so no group of the caller remains.
#'   After the switch the child can only read what that user can read,
#'   including the R libraries it lazy-loads code from: landlock's own
#'   functions are loaded beforehand, but functions of other packages used for
#'   the first time in the child must be readable by that user.
#' @param rlimits Named vector or list of resource limits, as in 'unix', for
#'   example `c(cpu = 60, fsize = 1e6)`. Each sets both the soft and the hard
#'   limit; zero and `NA` are ignored.
#' @param profile AppArmor profile for the child.
#' @param device Graphics device to use in the child.
#' @param policy A [policy()] applied in the child before `expr` runs. When
#'   given, every file descriptor the child inherited, except its standard
#'   streams, is pointed at `/dev/null` first, because Landlock does not
#'   revoke files that are already open. Connections and graphics devices
#'   inherited from the session are therefore unusable in the child.
#' @return The value of `expr`, visible or invisible as in the child. The
#'   report of the applied policy is available as [last_report()].
#'
#'   Under a `policy`, treat the value as data from an untrusted process. The
#'   package itself never evaluates what the child sends, but the value can
#'   contain closures, or environments whose active bindings run code when
#'   read. Return plain data (vectors, lists, data frames) from confined
#'   code, and be careful with anything else.
#' @export
#' @examples
#' eval_safe(rnorm(5))
#'
#' # errors keep their class
#' tryCatch(eval_safe(stop("oh no")), error = function(e) conditionMessage(e))
#'
#' # a wall-clock limit, enforced even inside C code
#' try(eval_safe(Sys.sleep(10), timeout = 1))
eval_safe <- function(expr, tmp = tempfile("fork"), std_out = stdout(), std_err = stderr(),
                      timeout = 0, priority = NULL, uid = NULL, gid = NULL, rlimits = NULL,
                      profile = NULL, device = pdf, policy = NULL, grace = 0) {
  orig_expr <- substitute(expr)
  env <- parent.frame()
  p <- merge_unix_args(policy, rlimits = rlimits, uid = uid, gid = gid, profile = profile)
  child <- function() {
    tryCatch({
      if (length(priority)) setpriority(priority)
      report <- if (!is.null(p)) apply_policy(p) else NULL
      if (length(device)) options(device = device)
      graphics.off()
      options(menu.graphics = FALSE)
      res <- withVisible(eval(orig_expr, env))
      serialize(list(ok = TRUE, value = res$value, visible = res$visible, report = report), NULL)
    }, error = function(e) {
      serialize(list(ok = FALSE, error = e), NULL)
    }, finally = graphics.off())
  }
  out <- fork_call(child, tmp = tmp, timeout = timeout, std_out = std_out, std_err = std_err,
                   close_fds = !is.null(p), remove_tmp = missing(tmp),
                   untrusted = !is.null(p), grace = grace)
  if (!is.null(out$report)) .state$last_report <- out$report
  if (!isTRUE(out$ok)) base::stop(out$error)
  if (isTRUE(out$visible)) out$value else invisible(out$value)
}

#' @rdname eval_safe
#' @export
eval_fork <- function(expr, tmp = tempfile("fork"), std_out = stdout(), std_err = stderr(),
                      timeout = 0, grace = 0) {
  orig_expr <- substitute(expr)
  env <- parent.frame()
  child <- function() {
    res <- tryCatch(list(ok = TRUE, value = eval(orig_expr, env)),
                    error = function(e) list(ok = FALSE, error = e))
    serialize(res, NULL)
  }
  out <- fork_call(child, tmp = tmp, timeout = timeout, std_out = std_out, std_err = std_err,
                   close_fds = FALSE, remove_tmp = missing(tmp), grace = grace)
  if (!isTRUE(out$ok)) base::stop(out$error)
  out$value
}

#' Run a program in a confined child process
#'
#' Forks, applies `policy` in the child, closes every inherited file
#' descriptor except the standard streams, and executes `cmd` (looked up in
#' `PATH`). Standard input is `/dev/null` unless `stdin` names a file.
#'
#' @param cmd Program to run.
#' @param args Character vector of arguments.
#' @param policy A [policy()], or `NULL` for none. Under a Landlock
#'   filesystem policy the program needs `exec` permission on itself and on
#'   the dynamic loader (`ld-linux*.so`, under `/lib`, `/lib64` or
#'   `/usr/lib`), which the kernel opens for execution as well, and `read`
#'   permission on its shared libraries; see [preset()].
#' @param timeout Wall-clock limit in seconds; `0` for none.
#' @param std_out,std_err `TRUE` to capture the output in the result, `FALSE`
#'   or `NULL` to discard it, or a file name, connection or function as in
#'   [eval_safe()].
#' @param env Named character vector of environment variables to set for the
#'   program.
#' @param clear_env If `TRUE`, the program starts with an empty environment
#'   plus `env`, instead of the session's environment plus `env`.
#' @param wd Working directory for the program; `NULL` keeps the session's.
#' @param umask File mode creation mask for the program, as for
#'   [Sys.umask()]; `NULL` keeps the session's.
#' @param stdin A file to connect to the program's standard input, opened
#'   before the policy applies (as a shell redirection would be); `NULL`
#'   for `/dev/null`.
#' @param grace Seconds between `SIGTERM` and `SIGKILL` when the timeout
#'   passes, so the program can clean up; `0` kills at once.
#' @return A list with `status` (exit status, `NA` if the program was killed
#'   by a signal), `signal` (the signal, or `NA`), and `stdout` and `stderr`
#'   (raw vectors when captured, else `NULL`). The report of the applied
#'   policy is available as [last_report()].
#' @export
#' @examples
#' res <- run("echo", "hello")
#' rawToChar(res$stdout)
run <- function(cmd, args = character(), policy = NULL, timeout = 0, std_out = TRUE,
                std_err = TRUE, env = NULL, clear_env = FALSE, wd = NULL, umask = NULL,
                stdin = NULL, grace = 0) {
  stopifnot(is.character(cmd), length(cmd) == 1L, is.character(args),
            is.logical(clear_env), length(clear_env) == 1L, !is.na(clear_env))
  if (!is.null(policy)) check_policy(policy)
  if (length(env) && (is.null(names(env)) || any(!nzchar(names(env)))))
    stop("env must be a named character vector", call. = FALSE)
  if (!is.null(wd)) {
    stopifnot(is.character(wd), length(wd) == 1L)
    if (!dir.exists(wd)) stop("wd: directory does not exist: ", wd, call. = FALSE)
    wd <- normalizePath(wd)
  }
  if (!is.null(stdin)) {
    stopifnot(is.character(stdin), length(stdin) == 1L)
    if (!file.exists(stdin)) stop("stdin: file does not exist: ", stdin, call. = FALSE)
    stdin <- normalizePath(stdin)
  }
  captured <- new.env(parent = emptyenv())
  sink_for <- function(x, which) {
    if (isTRUE(x)) {
      captured[[which]] <- list()
      function(chunk) captured[[which]][[length(captured[[which]]) + 1L]] <- chunk
    } else if (isFALSE(x)) NULL else x
  }
  child <- function() {
    res <- tryCatch({
      report <- if (!is.null(policy)) apply_policy(policy) else NULL
      .Call(C_write_frame, "R", serialize(report, NULL))
      if (clear_env) {
        keep <- Sys.getenv(c("TMPDIR", "TMP", "TEMP"), unset = NA)
        Sys.unsetenv(names(Sys.getenv()))
        keep <- keep[!is.na(keep)]
        if (length(keep)) do.call(Sys.setenv, as.list(keep))
      }
      if (length(env)) do.call(Sys.setenv, as.list(env))
      if (!is.null(wd)) setwd(wd)
      if (!is.null(umask)) Sys.umask(umask)
      simpleError(.Call(C_exec, cmd, args))
    }, error = function(e) e)
    serialize(list(ok = FALSE, error = res), NULL)
  }
  res <- fork_call(child, tmp = tempfile("run"), timeout = timeout,
                   std_out = sink_for(std_out, "out"), std_err = sink_for(std_err, "err"),
                   close_fds = TRUE, capture_r_output = FALSE, mode = "run",
                   remove_tmp = TRUE, untrusted = TRUE, stdin = stdin, grace = grace)
  joined <- function(which) if (is.null(captured[[which]])) NULL else do.call(c, c(list(raw()), captured[[which]]))
  list(status = res$exit_code, signal = res$signal, stdout = joined("out"), stderr = joined("err"))
}

# ---- internals -----------------------------------------------------------

# eval_safe()'s unix arguments, folded into the policy.
merge_unix_args <- function(policy, rlimits, uid, gid, profile) {
  if (!is.null(policy)) check_policy(policy)
  if (is.null(policy) && !length(rlimits) && !length(uid) && !length(gid) && !length(profile))
    return(NULL)
  p <- policy %||% new_policy()
  if (length(rlimits)) {
    lims <- unix_rlimits(rlimits)
    old <- p$limits %||% list()
    old[names(lims)] <- lims
    p$limits <- old
  }
  if (length(uid) || length(gid))
    p$ids <- resolve_ids(uid, gid)
  if (length(profile)) {
    stopifnot(is.character(profile), length(profile) == 1L)
    p$apparmor <- profile
  }
  p
}

# std_out / std_err -> list(fun = callback or NULL, close = connection to
# close afterwards or NULL), as in 'unix'.
output_callback <- function(x, default) {
  if (is.null(x) || isFALSE(x)) return(list(fun = NULL, close = NULL))
  if (isTRUE(x) || identical(x, "")) x <- default
  close <- NULL
  if (is.character(x)) {
    x <- file(normalizePath(x, mustWork = FALSE))
  }
  if (inherits(x, "connection")) {
    con <- x
    if (!isOpen(con)) {
      open(con, "wb")
      close <- con
    }
    fun <- if (identical(summary(con)$text, "text")) {
      function(chunk) {
        # A text connection cannot take NUL bytes; drop them rather than
        # fail (and kill the child) on binary output.
        cat(rawToChar(chunk[chunk != as.raw(0)]), file = con)
        flush(con)
      }
    } else {
      function(chunk) {
        writeBin(chunk, con = con)
        flush(con)
      }
    }
    return(list(fun = fun, close = close))
  }
  if (is.function(x)) {
    if (!length(formals(x))) stop("Function std_out must take at least one argument", call. = FALSE)
    return(list(fun = x, close = NULL))
  }
  stop("std_out and std_err must be TRUE, FALSE, a file name, a connection or a function",
       call. = FALSE)
}

# Fork, run child() there, collect. Returns the child's unserialized
# result (eval mode) or the process outcome (run mode).
fork_call <- function(child, tmp, timeout, std_out, std_err, close_fds,
                      capture_r_output = TRUE, mode = c("eval", "run"),
                      remove_tmp = FALSE, untrusted = FALSE, stdin = NULL, grace = 0) {
  mode <- match.arg(mode)
  out <- output_callback(std_out, stdout())
  err <- output_callback(std_err, stderr())
  on.exit({
    if (!is.null(out$close)) close(out$close)
    if (!is.null(err$close)) close(err$close)
  })
  if (length(timeout)) {
    stopifnot(is.numeric(timeout), !is.na(timeout[1]))
    timeout <- as.double(timeout[1])
  } else {
    timeout <- 0
  }
  if (!is.null(tmp)) {
    created <- !dir.exists(tmp)
    if (created) dir.create(tmp, recursive = TRUE, mode = "0700")
    tmp <- normalizePath(tmp)
    if (remove_tmp && created) on.exit(unlink(tmp, recursive = TRUE), add = TRUE)
  }
  stopifnot(is.numeric(grace), length(grace) == 1L, !is.na(grace), grace >= 0)
  load_namespace()
  max_result <- getOption("landlock.max_result", 2^31)
  if (!is.numeric(max_result) || length(max_result) != 1L || is.na(max_result) || max_result <= 0)
    stop("option landlock.max_result must be a positive number of bytes", call. = FALSE)
  wrapped <- function() {
    child_prepare(tmp, capture_r_output)
    on.exit(child_flush())
    child()
  }
  res <- .Call(C_fork_eval, wrapped, timeout, out$fun, err$fun, isTRUE(close_fds),
               as.double(max_result), stdin, as.double(grace))
  if (isTRUE(res$oversize))
    stop(sprintf("the child's result is larger than %s bytes (options(landlock.max_result))",
                 format(max_result, scientific = FALSE)), call. = FALSE)
  frames <- parse_frames(res$buffer)
  types <- vapply(frames, `[[`, character(1), "type")
  if (isTRUE(res$timed_out))
    stop(sprintf("timeout reached (%s sec)", format(timeout)), call. = FALSE)
  if ("F" %in% types)
    stop("child process setup failed: ", rawToChar(frames[[which(types == "F")[1]]]$body),
         call. = FALSE)
  first <- function(type) frames[[which(types == type)[1]]]$body

  if (mode == "run") {
    if ("R" %in% types) {
      report <- read_report(unserialize(first("R")))
      if (!is.null(report)) .state$last_report <- report
    }
    if ("P" %in% types) {
      outcome <- read_outcome(unserialize(first("P")), untrusted = TRUE)
      base::stop(outcome$error)
    }
    if (!"X" %in% types) stop(child_died_message(res), call. = FALSE)
    return(res)
  }

  if (!"P" %in% types) stop(child_died_message(res), call. = FALSE)
  read_outcome(unserialize(first("P")), untrusted = untrusted)
}

# Under a policy the child runs code that is not trusted, and once confined
# it can write anything to the result pipe, including a frame of its own
# making. So the session never evaluates what it receives: the outcome must
# be a plain list, its fields are read with .subset2() (an environment with
# an active binding would run code on `$`), and the report and the error
# are rebuilt from plain values. The returned value itself is the caller's
# data and is documented as untrusted.
read_outcome <- function(x, untrusted) {
  if (!untrusted) return(x)
  malformed <- function() stop("the child process returned a malformed result", call. = FALSE)
  if (typeof(x) != "list" || is.object(x)) malformed()
  ok <- .subset2(x, "ok")
  if (typeof(ok) != "logical" || length(ok) != 1L || is.na(ok)) malformed()
  if (ok) {
    vis <- .subset2(x, "visible")
    return(list(ok = TRUE, value = .subset2(x, "value"),
                visible = !identical(typeof(vis), "logical") || !identical(vis, FALSE),
                report = read_report(.subset2(x, "report"))))
  }
  list(ok = FALSE, error = read_condition(.subset2(x, "error")), report = NULL)
}

read_condition <- function(e) {
  plain_chr <- function(v) typeof(v) == "character" && !is.object(v)
  if (typeof(e) != "list") return(simpleError("the child process failed with an unreadable error"))
  msg <- .subset2(e, "message")
  msg <- if (plain_chr(msg) && length(msg) >= 1L) msg[[1]] else "error in the child process"
  call <- .subset2(e, "call")
  if (!is.null(call) && typeof(call) != "language") call <- NULL
  cls <- attr(e, "class", exact = TRUE)
  cls <- if (plain_chr(cls)) unique(c(setdiff(cls, c("error", "condition")), "error", "condition"))
         else c("simpleError", "error", "condition")
  structure(class = cls, list(message = msg, call = call))
}

read_report <- function(r) {
  if (is.null(r)) return(NULL)
  col <- function(name) {
    v <- if (typeof(r) == "list") .subset2(r, name) else NULL
    if (typeof(v) == "character" && !is.object(v)) v else NULL
  }
  layer <- col("layer"); status <- col("status"); detail <- col("detail")
  n <- length(layer)
  if (is.null(layer) || length(status) != n || length(detail) != n) return(NULL)
  abi <- attr(r, "landlock_abi", exact = TRUE)
  abi <- if (typeof(abi) == "integer" && length(abi) == 1L) abi else NA_integer_
  structure(data.frame(layer = layer, status = status, detail = detail, stringsAsFactors = FALSE),
            landlock_abi = abi, class = c("lk_report", "data.frame"))
}

# Result-pipe frames: type byte, 8-byte native double length, bytes. A
# truncated frame (the child died while writing) is dropped.
parse_frames <- function(buf) {
  # Indices are doubles: results may exceed 2^31 bytes.
  frames <- list()
  n <- as.double(length(buf))
  i <- 1
  while (i + 8 <= n) {
    type <- rawToChar(buf[i])
    len <- readBin(buf[(i + 1):(i + 8)], "double", size = 8L)
    if (!is.finite(len) || len < 0 || len != round(len)) break
    end <- i + 8 + len
    if (end > n) break
    body <- if (len > 0) buf[(i + 9):end] else raw()
    frames[[length(frames) + 1L]] <- list(type = type, body = body)
    i <- end + 1
  }
  frames
}

child_died_message <- function(res) {
  sig <- res$signal
  if (!is.na(sig)) {
    hint <- if (sig == SIGKILL) {
      "; for example the out-of-memory killer, a seccomp kill action, or q()"
    } else ""
    return(sprintf("child process has died before returning a result (signal %d, %s%s)",
                   sig, strsignal(sig), hint))
  }
  if (!is.na(res$exit_code))
    return(sprintf("child process has died before returning a result (exit status %d)", res$exit_code))
  "child process has died before returning a result"
}

# Package functions, and base R's, are lazy-loaded: the first use reads the
# installed .rdb. After a policy is applied the child may no longer be able to read it
# (Landlock rules that do not list the library, or a switch to another user
# who cannot enter the installing user's directories), so a function first
# used then, by apply_policy()'s later steps or by on.exit(), would fail and
# kill the child. Loading the whole namespace in the session once, before the
# first fork, means children only ever use what they inherited in memory.
load_namespace <- function() {
  if (isTRUE(.state$namespace_loaded)) return(invisible())
  ns <- asNamespace("landlock")
  for (name in ls(ns, all.names = TRUE)) get(name, envir = ns, inherits = FALSE)
  # Base R is lazy-loaded from base.rdb too: a child confined by chroot(),
  # by Landlock rules that leave out R.home(), or by a switch of user could
  # otherwise lose functions it needs to report its result (serialize()).
  base <- baseenv()
  for (name in ls(base, all.names = TRUE))
    try(get(name, envir = base, inherits = FALSE), silent = TRUE)
  # The attached exports may hold promises of their own.
  if ("package:landlock" %in% search()) {
    pkg <- as.environment("package:landlock")
    for (name in ls(pkg, all.names = TRUE)) get(name, envir = pkg, inherits = FALSE)
  }
  .state$namespace_loaded <- TRUE
  invisible()
}

# In the forked child, before any user code.
child_prepare <- function(tmp, capture_r_output) {
  # A normal R exit (q(), quit()) would run R's cleanup, which deletes the
  # session's temporary directory, shared with the parent. Exit finalizers
  # run before that cleanup, newest first: this one ends the child there.
  # The guard must stay reachable: such a finalizer also runs when its
  # object is garbage collected. A grandchild keeps the guards it inherited.
  guard <- new.env(parent = emptyenv())
  reg.finalizer(guard, function(e) .Call(C_child_abort), onexit = TRUE)
  .state$guards <- c(.state$guards, guard)
  .state$child_tmp <- tmp
  if (!is.null(tmp)) Sys.setenv(TMPDIR = tmp, TMP = tmp, TEMP = tmp)
  .state$sinks <- NULL
  # Route R-level output (cat, print, message, Rprintf) to the pipes on
  # fds 1 and 2 through sink(), not R's console, which a front-end such as
  # RStudio owns.
  if (capture_r_output && file.exists("/dev/fd/1") && file.exists("/dev/fd/2")) {
    out <- tryCatch(file("/dev/fd/1", open = "w", raw = TRUE), error = function(e) NULL)
    err <- tryCatch(file("/dev/fd/2", open = "w", raw = TRUE), error = function(e) NULL)
    if (!is.null(out) && !is.null(err)) {
      sink(out)
      sink(err, type = "message")
      .state$sinks <- list(out, err)
    }
  }
}

child_flush <- function() {
  for (con in .state$sinks) try(flush(con), silent = TRUE)
}
