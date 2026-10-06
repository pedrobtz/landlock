#' Ready-made policies
#'
#' Policies for common cases, built for the running session when called
#' (they read [R.home()], [.libPaths()] and [tempdir()]). Start from one and
#' add to it with the [policy()] verbs.
#'
#' Policies:
#'
#' * `"numeric"`: evaluate R code that only computes. Reads R, the
#'   installed packages and system libraries; reads and writes only the
#'   call's own temporary directory (the child's `TMPDIR`; see [fs()]); may execute nothing; no TCP; signals and abstract
#'   sockets scoped to the sandbox; the `"dangerous"`, `"no_exec"` and
#'   `"no_net"` system calls denied; all capabilities dropped.
#' * `"install"`: install a package from source. As `"numeric"`, plus
#'   executing the compiler toolchain (and the dynamic loader, which the
#'   kernel opens for execution too) and writing to `lib`; only the
#'   `"dangerous"` calls are denied.
#' * `"plumber"`: serve HTTP. As `"numeric"`, plus binding to `port`; the
#'   `"dangerous"` and `"no_exec"` calls are denied.
#'
#' System call sets, character vectors for [syscalls()] and
#' [seccomp_deny()]:
#'
#' * `"dangerous"`: calls a sandboxed R process has no use for and that
#'   widen the kernel's attack surface or escape a sandbox: `ptrace`,
#'   `process_vm_readv`, mounting, namespaces, keyrings, `bpf`,
#'   `perf_event_open`, `io_uring`, `userfaultfd`, kernel modules, `kexec`,
#'   `reboot`, swap, clock setting, `open_by_handle_at`, NUMA policy calls,
#'   `pidfd_getfd`, leaving the process group (`setsid`, `setpgid`, so that
#'   nothing outlives the call), `clone3` (see [seccomp_deny()]), and
#'   `landlock_*` and `seccomp` themselves (the sandbox is complete by
#'   the time the filter is installed). Never `set*id` or `capset`, which
#'   the later steps of [apply_policy()] use.
#' * `"no_exec"`: `execve` and `execveat` ([system()] stops working).
#' * `"no_net"`: socket creation and use. Also stops DNS, and is the only way
#'   to stop UDP without a network namespace.
#'
#' Paths that do not exist on this system are left out of the policies.
#'
#' @param name Name of the preset.
#' @param ... Arguments of the preset: `lib` for `"install"` (default the
#'   first library path), `port` for `"plumber"` (default 8000).
#' @return A [policy()], or for a system call set a character vector.
#' @export
#' @examples
#' preset("numeric")
preset <- function(name, ...) {
  stopifnot(is.character(name), length(name) == 1L)
  switch(name,
    numeric = preset_numeric(),
    install = preset_install(...),
    plumber = preset_plumber(...),
    dangerous = sc_dangerous,
    no_exec = sc_no_exec,
    no_net = sc_no_net,
    stop("unknown preset '", name, "'; available: numeric, install, plumber, ",
         "dangerous, no_exec, no_net", call. = FALSE)
  )
}

existing <- function(x) unique(x[nzchar(x) & file.exists(x)])

r_read_paths <- function() {
  existing(c(R.home(), .libPaths(), "/usr", "/lib", "/lib64", "/opt/R",
             "/etc/R", "/etc/ld.so.cache", "/etc/localtime", "/etc/timezone",
             "/etc/os-release", "/dev/urandom", "/dev/null"))
}

sc_dangerous <- c(
  "ptrace", "process_vm_readv", "process_vm_writev", "kcmp",
  "mount", "umount2", "pivot_root", "mount_setattr", "move_mount", "open_tree",
  "fsopen", "fsmount", "fsconfig", "fspick", "setns", "unshare",
  "keyctl", "add_key", "request_key", "userfaultfd", "perf_event_open", "bpf",
  "io_uring_setup", "io_uring_enter", "io_uring_register",
  "kexec_load", "kexec_file_load", "init_module", "finit_module", "delete_module",
  "reboot", "swapon", "swapoff", "acct", "quotactl", "syslog", "vhangup",
  "open_by_handle_at", "name_to_handle_at",
  "mbind", "set_mempolicy", "migrate_pages", "move_pages",
  "settimeofday", "clock_settime", "adjtimex", "clock_adjtime",
  "sethostname", "setdomainname", "personality", "ioperm", "iopl", "lookup_dcookie",
  "clone3", "pidfd_getfd", "setsid", "setpgid",
  "landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self", "seccomp"
)

sc_no_exec <- c("execve", "execveat")

sc_no_net <- c("socket", "socketcall", "socketpair", "connect", "bind", "listen", "accept",
               "accept4", "sendto", "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg")

landlock_base <- function() {
  # The call's own scratch directory, read and write; never the session's
  # tempdir(), which the session may later trust (cached shared libraries,
  # knitr caches, .rds files).
  p <- fs(policy(), read = r_read_paths(), rw = existing("/dev/null"), tmp = TRUE)
  scope(net(p))
}

preset_numeric <- function() {
  p <- syscalls(landlock_base(), deny = c(sc_dangerous, sc_no_exec, sc_no_net))
  caps(p)
}

preset_install <- function(lib = .libPaths()[1]) {
  stopifnot(is.character(lib), length(lib) == 1L)
  p <- fs(landlock_base(), read = existing(c("/etc", "/bin", "/sbin")),
          exec = existing(c(R.home(), "/usr/bin", "/bin", "/usr/lib", "/usr/lib64", "/lib",
                            "/lib64", "/usr/libexec", "/usr/local/bin", "/opt/R")),
          write = lib)
  caps(syscalls(p, deny = sc_dangerous))
}

preset_plumber <- function(port = 8000) {
  p <- net(landlock_base(), bind = port)
  caps(syscalls(p, deny = c(sc_dangerous, sc_no_exec)))
}
