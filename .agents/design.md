# landlock — process confinement for R, in pure C

Package name: `landlock` — named after its core mechanism, the way `curl`,
`openssl`, `sodium` and `RAppArmor` are (see §16). Successor to the sandboxing
half of `unix`: fork-then-restrict, one-way operations, result serialised back,
timeout enforced by the parent — plus the kernel features that did not exist in
2013: Landlock, seccomp-bpf, user/mount/net/pid namespaces, capabilities,
cgroup v2.

Status of this document: design frozen enough to start coding. Open decisions are
collected in §17. Revised 2026-10-06 after review against the package skeleton,
the `unix` sources and CRAN policy; the release plan is in [roadmap.md](roadmap.md).
Release 0.1.0 is M1 + M2 (§14); M3–M5 ship in 0.2.0 and later.

---

## 1. Goals and non-goals

Goals

1. Policy is data, mechanism is hidden. A policy is an R list (serialisable to
   TOML/JSON later) that an administrator can own; the package compiles it into
   an ordered sequence of kernel operations.
2. Probe, enforce, report. `status()` says what this kernel offers. Every
   enforcement returns which layers were actually applied. `strict = TRUE`
   fails if any requested layer is unavailable; the default is best-effort with
   an explicit report, never a silent no-op.
3. Three execution models over one policy:
   - `confine(policy)` — restrict the current session (irreversible).
   - `eval_safe(expr, policy)` — fork, restrict the child, keep evaluating R
     there (the `unix` model).
   - `run(cmd, args, policy)` — fork, restrict, exec a binary.
4. Pure C, no external libraries. No libseccomp, libcap, libapparmor, libminijail.
   Vendored uapi constants only (§10).
5. Linux-first; rlimits + timeout work everywhere POSIX; confinement layers are
   Linux-only and degrade with a report.

Non-goals (v1)

- OCI images, rootfs management, networking setup (bridges, veth).
- Running as a long-lived service.
- macOS Seatbelt (later, same policy object).

---

## 2. What this environment taught us (Ubuntu 24.04 userland, kernel 6.18)

| Item | Finding | Consequence |
|---|---|---|
| Landlock | ABI **7** reported by `landlock_create_ruleset(NULL,0,VERSION)` | audit-log flags usable; `trace()` can use kernel audit |
| `/usr/include/linux/landlock.h` (Ubuntu 24.04 headers) | has `REFER`, `TRUNCATE`, net TCP; **lacks** `IOCTL_DEV`, `LANDLOCK_SCOPE_*`, `LANDLOCK_RESTRICT_SELF_LOG_*` | must vendor a compat header; never rely on build-host headers for constants |
| `seccomp.h` | has `SECCOMP_RET_LOG`, `SECCOMP_FILTER_FLAG_LOG` | complain-mode via `RET_LOG` is available |
| cgroups | **v1** mounted here, no `cgroup.controllers` | cgroup layer must detect v1 vs v2 and skip v1 (report) |
| user namespaces | `max_user_namespaces` = 32046, no `apparmor_restrict_unprivileged_userns` sysctl | not AppArmor-gated here; it will be on Ubuntu desktop/server ≥ 24.04 |
| R | not installed, not installable (no apt source) | the C core must build and test **without R** (§3) |
| uid | root inside the workspace | tests must also run as non-root in CI |

---

## 3. Package layout

```
landlock/
├── DESCRIPTION            OS_type: unix, SystemRequirements, Copyright: file inst/COPYRIGHTS
├── NAMESPACE              useDynLib(landlock, .registration = TRUE)
├── LICENSE                MIT
├── LICENSE.note           uapi header excerpts: GPL-2.0 WITH Linux-syscall-note
├── tools/
│   └── gen_syscalls.sh    emits src/sc_table.h from a name list (output is committed)
├── R/
│   ├── status.R           status(), probes
│   ├── policy.R           policy(), fs(), net(), syscalls(), limits(), namespaces(), caps(), presets
│   ├── apply.R            apply_policy() — the ordered engine (R side), confine()
│   ├── restrict.R         restrict_self() thin Landlock wrapper
│   ├── seccomp.R          seccomp_deny(), syscall_table(), syscall presets
│   ├── caps.R             caps_*(), no_new_privs()
│   ├── ns.R               ns_unshare(), ns_map_ids(), mount_*()
│   ├── cgroup.R           cgroup_v2(), cgroup_limit()   (pure R: file writes)
│   ├── limits.R           rlimit(), rlimit_*(), setids(), chroot()
│   ├── eval_safe.R        eval_safe(), eval_fork(), run()
│   └── compat-unix.R      aliases matching unix:: names
├── src/
│   ├── Makevars           PKG_CPPFLAGS = -I. -D_GNU_SOURCE
│   ├── lk.h             internal C API — NO R headers
│   ├── compat/
│   │   ├── landlock_compat.h
│   │   ├── seccomp_compat.h
│   │   └── caps_compat.h
│   ├── sc_table.h         generated syscall table (see §5.2)
│   ├── ll.c               Landlock
│   ├── sc.c               seccomp-bpf
│   ├── caps.c             capabilities, no_new_privs
│   ├── ns.c               unshare, id maps, mounts, hostname          (0.2.0)
│   ├── lim.c              rlimit, setids, chroot
│   ├── proc.c             fork, pipes, fd hygiene, poll-collect wait, child exit
│   ├── rglue.c            .Call wrappers  — the ONLY file including <Rinternals.h>
│   └── init.c             R_registerRoutines, R_useDynamicSymbols(dll, FALSE)
├── tests/
│   ├── c/                 Makefile + harness linking ll.c sc.c caps.c ns.c lim.c proc.c
│   │   ├── test_ll.c      deny /etc read → EACCES; allow tempdir → ok
│   │   ├── test_sc.c      deny getppid → EPERM; RET_LOG path
│   │   ├── test_caps.c    bounding set empty after drop
│   │   ├── test_ns.c      unshare(USER|NS) + id map; mount tmpfs       (0.2.0)
│   │   ├── test_lim.c     RLIMIT_NOFILE lowered → open() fails with EMFILE
│   │   └── test_proc.c    fork + pipe + timeout kill; 1 MiB output; close_from
│   └── testthat/          R-level tests (skip_if(status()$landlock_abi == 0) etc.)
└── inst/
    ├── COPYRIGHTS         Linux uapi constants: GPL-2.0 WITH Linux-syscall-note
    ├── WORDLIST           spelling
    └── policies/          TOML presets: numeric.toml, install.toml, plumber.toml (0.2.0)
```

`.Rbuildignore` excludes `.agents/`, `tests/c/` and `cran-comments.md`: the
first is a hidden directory (`R CMD check` NOTE), the second is for CI only.
`tools/` is a standard package directory and ships in the tarball.

Rule: `ll.c sc.c caps.c ns.c lim.c proc.c` compile with
`gcc -std=gnu11 -Wall -Wextra -pedantic -D_GNU_SOURCE -I src` and link into the C
harness with no R present. They are a reusable C library (the "small C library"
this started from). `rglue.c` is the only adapter.

Non-Linux builds: CRAN checks the package on macOS, so every file must compile
there. Each Linux-only function body in `ll.c`, `sc.c`, `caps.c` (and later
`ns.c`) is wrapped `#ifdef __linux__ … #else return -ENOSYS; #endif`; `lk.h`
declares the full API on every platform; `lim.c` and `proc.c` are plain POSIX.
No `configure` script. `OS_type: unix` keeps Windows out of CRAN's matrix.
Prototypes use `(void)` for empty parameter lists: R-devel checks compile with
`-Wstrict-prototypes`.

Error convention for the core: return `0` on success, `-errno` on failure.
Functions that return a value return `>= 0` on success, `-errno` otherwise.
No `fprintf`, no `exit`, no `_exit` (§5.6), no globals except the syscall table.

---

## 4. Enforcement order (the part that must not be reordered)

Applied in the child (or the current process for `confine()`):

```
 0. fd hygiene    close every fd except 0/1/2 and the pipe write ends (child only; §11)
 1. cgroup        join/create sub-cgroup, write limits        (needs: write access to own cgroup dir)
 2. unshare user  CLONE_NEWUSER, then write setgroups/uid_map/gid_map
 3. unshare rest  CLONE_NEWNS | NEWPID | NEWNET | NEWIPC | NEWUTS | NEWCGROUP
 4. hostname      sethostname (needs NEWUTS)
 5. mounts        make / rprivate; bind ro; tmpfs; remount ro      (needs NEWNS, CAP_SYS_ADMIN in the userns)
 6. chroot        optional                                          (needs CAP_SYS_CHROOT)
 7. landlock      create ruleset, add rules, no_new_privs, restrict_self
 8. capabilities  drop bounding set, clear ambient, clear sets
 9. no_new_privs  prctl (idempotent; also done inside 7)
10. seccomp       install filter with TSYNC
11. setids        setgroups, setresgid, setresuid
12. rlimits       setrlimit each
13. eval / exec
```

Why this order:
- Mounts need `CAP_SYS_ADMIN` in the user namespace, so they come before caps are
  dropped and before seccomp could deny `mount`.
- Landlock before caps: `landlock_restrict_self` needs no special capability but
  needs `no_new_privs` (or `CAP_SYS_ADMIN`); doing it before seccomp means the
  filter can deny the `landlock_*` syscalls afterwards.
- seccomp last among the one-way layers so the filter can deny `unshare`,
  `setns`, `mount`, `capset`, `prctl(PR_CAPBSET_READ)` without breaking setup.
- `setids` comes after seccomp, so the filter must allow `setgroups`,
  `setresgid`, `setresuid`; presets never deny them. Dropping the uid last
  mirrors `unix::eval_safe`.
- rlimits last because `RLIMIT_NOFILE` / `RLIMIT_AS` could break the earlier
  steps (ruleset fds, mmap during setup).

Step 0 comes first because Landlock does not revoke already-open fds: an
inherited fd to a file outside the allowed hierarchy is a hole. In 0.1.0 the
engine applies steps 0, 7, 8, 9, 10, 11, 12, 13; the others are 0.2.0 (§14).

PID namespace note: `unshare(CLONE_NEWPID)` affects **children** of the caller,
not the caller. In `eval_safe`, the forked child unshares, then the evaluation
runs in that same child, which is therefore *not* in the new pid namespace.
Decided (§17.2): `namespaces("pid")` is honoured only by `run()` (fork → unshare →
fork again → exec; the middle process is PID 1 and reaps). `eval_safe` reports
pid-ns as skipped.

---

## 5. C core API (`src/lk.h`)

### 5.1 Landlock (`ll.c`)

```c
int lk_ll_abi(void);
/* >0: ABI version; 0: not available (ENOSYS, EOPNOTSUPP = disabled at boot); <0: -errno */

enum { LK_LL_READ = 1, LK_LL_WRITE = 2, LK_LL_EXEC = 4 };

struct lk_ll_path  { const char *path; unsigned mode; };     /* mode: OR of LK_LL_* */

struct lk_ll_policy {
    const struct lk_ll_path *paths;  size_t npaths;
    int handle_net;                    /* 1 = mediate TCP; allow-lists below   */
    const uint16_t *bind_ports;        size_t nbind;
    const uint16_t *connect_ports;     size_t nconnect;
    int scope_signal, scope_abstract_unix;
    int log;                           /* OR of LK_LL_LOG_* (ABI 7), 0 = default */
    int best_effort;                   /* 1: mask to ABI; 0: -ENOTSUP if anything unsupported */
};

struct lk_ll_report { int abi; int fs; int net; int scope; int log; }; /* 1 applied / 0 skipped */

int lk_ll_restrict(const struct lk_ll_policy *p, struct lk_ll_report *r);
```

Algorithm:

1. `abi = lk_ll_abi()`; if 0 and best_effort → return 0 with report all-zero.
2. `handled_fs` = union of rights known for `abi` (table in §9). Always handle
   every right the ABI knows: default-deny is the point.
3. `handled_net` = BIND|CONNECT if `handle_net && abi >= 4`.
4. `scoped` = requested scope bits if `abi >= 6`.
5. `landlock_create_ruleset(&attr, sizeof attr, 0)` → fd. Note `sizeof` must be
   the size *for that ABI* (`offsetofend` of the last field the ABI knows), or
   the kernel returns `E2BIG`/`EINVAL`. Compute it from `abi`.
6. For each path: `open(path, O_PATH|O_CLOEXEC)`; `fstat`; `allowed` = rights for
   `mode` (§9) masked by `handled_fs`; if not a directory, mask further with
   `ACCESS_FILE = EXECUTE|WRITE_FILE|READ_FILE|TRUNCATE|IOCTL_DEV` (the kernel
   rejects directory-only rights on files). `landlock_add_rule(fd,
   LANDLOCK_RULE_PATH_BENEATH, &pb, 0)`. Close the path fd.
7. For each port: `landlock_add_rule(fd, LANDLOCK_RULE_NET_PORT, &np, 0)`.
8. `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`.
9. `landlock_restrict_self(fd, flags)` with `flags = log` if `abi >= 7` else 0.
10. Close ruleset fd, fill report.

Threads: `landlock_restrict_self` restricts the **calling thread** and its
future children. Pre-existing threads (BLAS pool, parallel workers) stay
unrestricted. This is harmless in `eval_safe` (a forked child has one thread)
and a documented caveat for `confine()`.

### 5.2 seccomp (`sc.c`)

```c
enum { LK_SC_ERRNO = 0, LK_SC_KILL_PROCESS = 1, LK_SC_LOG = 2, LK_SC_TRAP = 3 };

size_t      lk_sc_count(void);
const char *lk_sc_name_at(size_t i, int *nr);
int         lk_sc_lookup(const char *name);            /* nr or -ENOENT */
int         lk_sc_status(void);                        /* 0 none, 1 strict, 2 filter */
int         lk_sc_deny(const int *nrs, size_t n, int action, int errnum);
```

Syscall table: ~160 names, each entry guarded by `#ifdef SYS_<name>` so the
table is exactly the build architecture's, with no hand-maintained numbers
(a preprocessor X-macro cannot emit `#ifdef`, so the guarded blocks are
generated by `tools/gen_syscalls.sh` from a plain name list and the generated
`sc_table.h` is committed; the build has no generator step):

```c
static const struct { const char *name; int nr; } table[] = {
#ifdef SYS_ptrace
    { "ptrace", SYS_ptrace },
#endif
#ifdef SYS_io_uring_setup
    { "io_uring_setup", SYS_io_uring_setup },
#endif
    /* ... */
};
```

Filter layout (classic BPF, `struct sock_filter`):

```
LD  W ABS  offsetof(struct seccomp_data, arch)
JEQ K  AUDIT_ARCH_CURRENT   jt=1 jf=0
RET KILL_PROCESS
LD  W ABS  offsetof(struct seccomp_data, nr)
#if x86_64
JGE K  X32_SYSCALL_BIT (0x40000000)  jt=0 jf=1
RET KILL_PROCESS
#endif
for each denied nr:
  JEQ K nr  jt=0 jf=1
  RET action            (ERRNO|errnum, KILL_PROCESS, LOG, TRAP)
RET ALLOW
```
2 instructions per syscall, well under the 4096 limit. `AUDIT_ARCH_CURRENT`
chosen at compile time from `__x86_64__`, `__aarch64__`, `__riscv`, `__powerpc64__`
(little-endian), `__s390x__`.

Install: `prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)`, then
`syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog)`;
on `EINVAL` retry without TSYNC and report; if `SYS_seccomp` is undefined fall
back to `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)`.
TSYNC matters for `confine()`: without it only the calling thread is filtered.
TSYNC also propagates `no_new_privs` to the other threads.

Deny-list, not allow-list, for v1: R's syscall footprint is wide and varies with
BLAS and packages. Presets:

- `dangerous`: ptrace, process_vm_readv/writev, mount, umount2, pivot_root,
  setns, unshare, keyctl, add_key, request_key, userfaultfd, perf_event_open,
  bpf, io_uring_setup/enter/register, kexec_load, kexec_file_load, init_module,
  finit_module, delete_module, reboot, swapon, swapoff, open_by_handle_at,
  name_to_handle_at, mbind, set_mempolicy, migrate_pages, move_pages, acct,
  settimeofday, clock_settime, adjtimex, clock_adjtime, sethostname,
  setdomainname, quotactl, syslog, vhangup, personality, ioperm, iopl,
  landlock_create_ruleset/add_rule/restrict_self (after our own use), seccomp.
- `no_exec`: execve, execveat (R `system()` dies).
- `no_net`: socket, socketpair, connect, bind, listen, accept, accept4, sendto,
  recvfrom, sendmsg, recvmsg (also kills DNS; the only way to cut UDP without a
  net namespace).

### 5.3 Capabilities (`caps.c`)

```c
int lk_cap_last(void);                         /* /proc/sys/kernel/cap_last_cap, fallback 40 */
int lk_cap_lookup(const char *name);           /* "sys_admin" → CAP_SYS_ADMIN */
int lk_caps_drop_bounding(const int *keep, size_t nkeep); /* PR_CAPBSET_DROP every cap not in keep */
int lk_caps_clear(const int *keep, size_t nkeep);         /* capset v3: permitted/effective/inheritable = keep; ambient cleared */
int lk_nnp_set(void);
int lk_nnp_get(void);                           /* 0/1 */
```
`capset` via `syscall(SYS_capset, &hdr, data[2])` with
`_LINUX_CAPABILITY_VERSION_3`; ambient via `prctl(PR_CAP_AMBIENT,
PR_CAP_AMBIENT_CLEAR_ALL)`. Reading current sets: R parses `/proc/self/status`
(`CapEff`, `CapPrm`, `CapInh`, `CapBnd`, `CapAmb`); no C needed.

### 5.4 Namespaces and mounts (`ns.c`)

```c
enum { LK_NS_USER=1, LK_NS_MNT=2, LK_NS_PID=4, LK_NS_NET=8, LK_NS_IPC=16, LK_NS_UTS=32, LK_NS_CGROUP=64 };
int lk_unshare(unsigned ns);                            /* user first if requested, then the rest */
int lk_map_self_ids(uid_t inner_uid, gid_t inner_gid);  /* "deny" → setgroups; "<inner> <outer> 1" → uid_map, gid_map */
int lk_mount_private_all(void);                         /* mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL) */
int lk_mount_bind(const char *src, const char *dst, int readonly); /* bind, then remount MS_BIND|MS_REMOUNT|MS_RDONLY */
int lk_mount_tmpfs(const char *dst, const char *opts);  /* e.g. "size=64m,mode=0700" */
int lk_mount_remount_ro(const char *path);
int lk_sethostname(const char *name);
```
Default id map keeps the caller's uid (`inner = outer`), so files stay owned by
the user and nothing looks like root. `inner = 0` is opt-in (needed for mounts
in some setups; mounts inside a userns need `CAP_SYS_ADMIN` in that ns, which
the creator has regardless of the mapped uid).

### 5.5 Limits and ids (`lim.c`)

```c
int lk_rlimit_lookup(const char *name);                 /* "as" → RLIMIT_AS */
int lk_rlimit_get(int res, uint64_t *soft, uint64_t *hard);
int lk_rlimit_set(int res, uint64_t soft, uint64_t hard);   /* UINT64_MAX = RLIM_INFINITY */
int lk_setids(uid_t uid, gid_t gid);                    /* setgroups(1,&gid), setresgid, setresuid */
int lk_chroot(const char *path);                        /* chroot + chdir("/") */
```

### 5.6 Process plumbing (`proc.c`)

```c
pid_t lk_fork(void);
int   lk_pipe(int fds[2]);                               /* O_CLOEXEC */
int   lk_dup2(int from, int to);
int   lk_write_all(int fd, const void *buf, size_t len);
int   lk_close_from(int lowfd, const int *keep, size_t nkeep);
/* close_range(2) where available, else iterate /proc/self/fd (Linux) or /dev/fd (macOS) */
struct lk_buf { char *data; size_t len, cap; };
int   lk_wait_collect(pid_t pid, const int *fds, size_t nfds, int slice_ms,
                        struct lk_buf *bufs, int *status, int *done);
/* ONE poll() slice of at most slice_ms: drains every readable fd into its buffer,
   handles EINTR, reaps with waitpid(WNOHANG) once every fd hit EOF. Sets *done.
   Returns 0 or -errno. The caller loops; between slices rglue.c calls
   R_CheckUserInterrupt() and enforces the wall-clock timeout, so Ctrl-C works
   and the core stays free of R. Draining while waiting avoids the 64 KiB pipe deadlock. */
int   lk_kill(pid_t pid, int sig);
void  lk_child_exit(const int *fds, size_t nfds);
/* close the given write ends, then raise(SIGKILL). Never returns. */
```

Why `raise(SIGKILL)` and not `_exit()`: `R CMD check` flags compiled code that
references `exit`, `_exit` or `abort` ("entry points which might terminate R"),
and a first CRAN submission should carry no NOTE that needs a justification.
`unix` does exactly this in `fork.c`. The consequence is that the parent can no
longer read "terminated by signal" as failure; see §6.3 for the discriminator.

---

## 6. R-level API

### 6.1 Policy object

```r
p <- policy() |>
  fs(read  = c("/usr", "/etc/R", "/etc/ld.so.cache", .libPaths()),
     write = tempdir(),
     exec  = c("/usr/lib/R", "/usr/bin")) |>
  net("none")                                  # "none" | "tcp" | list(bind=, connect=)
  syscalls(deny = c(preset("dangerous"), "execve"), action = "errno") |>
  caps(drop = "all") |>
  namespaces("user", "mount", "net") |>
  mounts(tmpfs = "/tmp", bind_ro = list("/usr" = "/usr")) |>
  limits(memory = "1g", pids = 32, cpu = 60, fsize = "100m", nofile = 256) |>
  ids(uid = NULL, gid = NULL) |>
  options(timeout = 30, best_effort = TRUE, log = FALSE)
```

Stored as a plain named list with class `lk_policy`; `print()` shows layers and
which ones the current kernel can honour (`explain(p)` is `print` plus the
operation sequence). `read_policy("x.toml")` / `write_policy()` come in M5.

`fs()` semantics map to Landlock rights (§9). Paths that don't exist are an
error at `apply` time, not at build time, so policies are portable.

`limits()`: `memory` → `RLIMIT_AS` in 0.1.0; from 0.2.0 cgroup `memory.max`
when a delegated cgroup v2 is available (then `RLIMIT_AS` is not set, because it
breaks mmap-heavy BLAS; document `OPENBLAS_NUM_THREADS=1` meanwhile); `pids` →
`RLIMIT_NPROC` (cgroup `pids.max` from 0.2.0); `cpu` → `RLIMIT_CPU` (seconds);
`timeout` is wall-clock, enforced by the parent.

Presets, loaded by `preset("name")`. In 0.1.0 they are R objects in
`R/presets.R`, built from `.libPaths()`, `R.home()` and `tempdir()` at call
time; the TOML files in `inst/policies/` and `read_policy()` arrive with M5.
- `numeric`: read R + libs, write tempdir, no net, deny dangerous + exec.
- `install`: as numeric plus exec of compiler toolchain, write to a given lib dir.
- `plumber`: as numeric with TCP connect allowed to listed ports.

Syscall presets (`preset("dangerous")`, `"no_exec"`, `"no_net"`) are character
vectors; see §5.2.

### 6.2 Functions

```r
status()                      # list: landlock_abi, seccomp (0/1/2), no_new_privs, caps (named list of hex),
                              #   userns (max_user_namespaces, unprivileged_userns_clone, apparmor_restrict_unprivileged_userns, works),
                              #   cgroup (version, path, delegated), apparmor_enabled, kernel
apply_policy(p, strict = FALSE)   # engine; returns lk_report (which layers applied / skipped / why)
confine(p, force = FALSE)     # apply_policy on the current process; errors if multi-threaded unless force (§17.3)
eval_safe(expr, tmp = tempfile("fork"), std_out = stdout(), std_err = stderr(),
          timeout = 0, priority = NULL, uid = NULL, gid = NULL, rlimits = NULL,
          profile = NULL, device = pdf, policy = NULL)
eval_fork(expr, tmp = tempfile("fork"), std_out = stdout(), std_err = stderr(), timeout = 0)
run(cmd, args = character(), policy = NULL, timeout = 0, stdout = TRUE, stderr = TRUE, env = NULL)

restrict_self(read, write, exec, tcp_bind, tcp_connect, scope = c("signal", "abstract_unix"),
         best_effort = TRUE, log = NULL)
seccomp_deny(syscalls, action = c("errno", "kill", "log", "trap"), errno = "EPERM")
seccomp_status(); syscall_table()
caps_drop_all(); caps_keep(...); no_new_privs()
ns_unshare(user = FALSE, mount = FALSE, pid = FALSE, net = FALSE, ipc = FALSE, uts = FALSE, cgroup = FALSE)
ns_map_ids(uid = getuid(), gid = getgid())
mount_private(); mount_bind(src, dst, readonly = TRUE); mount_tmpfs(dst, size = "64m"); mount_ro(path)
rlimit(resource, soft, hard = soft); rlimit_as(); rlimit_cpu(); ...    # unix names
setids(uid, gid); chroot(path); sethostname(name)
cgroup_v2(); cgroup_limit(memory = NULL, pids = NULL, cpu = NULL)
trace(expr, policy = NULL)     # M5: run with landlock log + seccomp RET_LOG, parse audit → suggested policy
```

`eval_safe()` keeps `unix::eval_safe()`'s argument list verbatim (checked
against `unix/R/fork.R`: `expr, tmp, std_out, std_err, timeout, priority, uid,
gid, rlimits, profile, device`) and appends `policy` as the last named argument,
so every positional call written for `unix` keeps working. `tmp` is the child's
temp directory as in `unix`; `device` is set in the child; `profile` errors
unless `NULL` until the AppArmor layer lands (§15). `rlimits`, `uid`, `gid` and
`priority` are merged into the policy as a convenience.

`compat-unix.R` exports the `unix::` names (`eval_safe`, `eval_fork`,
`rlimit_*`, `setuid`, `setgid`, `getuid`, `getgid`, `chroot`, `aa_*` stubs that
error with "AppArmor layer not implemented; see §15") so it is a drop-in.

### 6.3 `eval_safe` engine

```
parent:  pr <- pipe (result), po <- pipe (stdout), pe <- pipe (stderr)
         pid <- .Call(C_fork)
child:   close read ends; dup2(po[2] → 1); dup2(pe[2] → 2)
         .Call(C_close_from, 3L, keep = c(pr[2], 1L, 2L))   # step 0 of §4
         (optional) setpriority; options(device = device); tempdir ← tmp
         report <- apply_policy(policy)               # may error → caught below
         out <- tryCatch(
                  list(value = eval(expr, envir), report = report),
                  error = function(e) list(error = e))   # keep the condition object, not just the message
         .Call(C_write_raw, pr[2], serialize(out, NULL))
         .Call(C_child_exit, pr[2])                     # close, raise(SIGKILL): no finalizers, no parent on.exit
parent:  close write ends
         repeat .Call(C_wait_collect, pid, fds, slice_ms = 200)   # rglue loop:
             R_CheckUserInterrupt() between slices; on interrupt kill(SIGKILL), drain, reap, rethrow
             if elapsed > timeout → kill(SIGKILL), drain, reap, timed_out = TRUE
         write res$bufs[[2]] to std_out, [[3]] to std_err
         if timed_out → stop("eval_safe: timeout after N s")
         if unserialize(res$bufs[[1]]) succeeds → normal exit (the child always ends by SIGKILL)
             if out$error → stop(out$error) else out$value with attr(,"report")
         else → stop("child killed by signal X before returning a result (seccomp kill? OOM?)")
```

The result pipe is the discriminator, not the wait status: a complete
serialized payload means success regardless of how the child ended; SIGKILL
with an empty or truncated payload means timeout, seccomp `kill` or the OOM
killer. The `_exit()` alternative and why it was rejected are in §5.6.

Notes
- `serialize()` materialises ALTREP vectors, so compact sequences and
  memory-mapped vectors cross the pipe as plain data. Objects holding external
  pointers (connections, DuckDB handles, Rcpp XPtr) come back as null pointers;
  document.
- The child must not touch graphics devices or parent connections; `unix` sets
  `options(device = pdf)`; do the same.
- `std_out = NULL` discards; a connection receives the bytes after the child
  exits (streaming while running is M4).
- `parallel::mcfork` precedent for forking an R session: after fork the child
  must never return into the parent's event loop; always `_exit`.

---

## 7. `status()` probe details

| Field | Source |
|---|---|
| `landlock_abi` | `lk_ll_abi()` (0 = unsupported or disabled at boot; `/sys/kernel/security/lsm` lists `landlock` when enabled) |
| `seccomp` | `prctl(PR_GET_SECCOMP)` → 0/1/2; `Seccomp_filters` from `/proc/self/status` |
| `no_new_privs` | `prctl(PR_GET_NO_NEW_PRIVS)` |
| `caps` | parse `/proc/self/status` Cap* lines → named hex strings + decoded names |
| `userns.max` | `/proc/sys/user/max_user_namespaces` |
| `userns.unprivileged_clone` | `/proc/sys/kernel/unprivileged_userns_clone` (Debian/Ubuntu legacy; absent = allowed) |
| `userns.apparmor_restricted` | `/proc/sys/kernel/apparmor_restrict_unprivileged_userns` (Ubuntu ≥ 23.10) |
| `userns.works` | fork a child that calls `unshare(CLONE_NEWUSER)`; the only reliable test |
| `cgroup.version` | `/sys/fs/cgroup/cgroup.controllers` exists → 2 else 1 (or 0) |
| `cgroup.path` | `/proc/self/cgroup` line `0::` |
| `cgroup.delegated` | can `mkdir` under own cgroup dir and `cgroup.subtree_control` is writable |
| `apparmor` | `/sys/module/apparmor/parameters/enabled` == "Y"; current profile from `/proc/self/attr/apparmor/current` |
| `kernel` | `uname -r` |

---

## 8. cgroup v2 layer (pure R)

```
own  <- "/sys/fs/cgroup" + path from /proc/self/cgroup (line 0::)
sub  <- file.path(own, paste0("landlock-", pid))
dir.create(sub)                                    # fails without delegation → report "skipped: not delegated"
write "+memory +pids +cpu" to own/cgroup.subtree_control  (may fail if own has processes: cgroup v2 "no internal processes" rule)
write memory.max, pids.max, cpu.max ("max 100000" / "50000 100000")
write "0" to sub/cgroup.procs                      # move self (then the forked child inherits)
cleanup: parent rmdir(sub) after wait (R side)
```
Rootless on systemd hosts: works inside `systemd-run --user --scope` or when
`Delegate=` is set on the user slice. Kubernetes pods: usually not delegated →
skipped with a report; `limits()` then falls back to rlimits.

---

## 9. Landlock right mapping

ABI → handled filesystem rights (always handle everything the ABI knows):

| ABI | kernel | adds |
|---|---|---|
| 1 | 5.13 | EXECUTE, WRITE_FILE, READ_FILE, READ_DIR, REMOVE_DIR, REMOVE_FILE, MAKE_CHAR, MAKE_DIR, MAKE_REG, MAKE_SOCK, MAKE_FIFO, MAKE_BLOCK, MAKE_SYM |
| 2 | 5.19 | REFER |
| 3 | 6.2 | TRUNCATE |
| 4 | 6.7 | net: BIND_TCP, CONNECT_TCP |
| 5 | 6.10 | IOCTL_DEV |
| 6 | 6.12 | scoped: ABSTRACT_UNIX_SOCKET, SIGNAL |
| 7 | 6.14/6.15 | restrict_self flags: LOG_SAME_EXEC_OFF, LOG_NEW_EXEC_ON, LOG_SUBDOMAINS_OFF |

`fs()` mode → allowed rights (masked by handled, and by ACCESS_FILE for non-dirs):

| mode | rights |
|---|---|
| read | READ_FILE, READ_DIR |
| write | WRITE_FILE, REMOVE_DIR, REMOVE_FILE, MAKE_* (all), REFER, TRUNCATE, IOCTL_DEV |
| exec | EXECUTE (plus READ_FILE: the loader needs it) |

`write` does not imply `read`; callers combine. `REFER` only matters across
hierarchies; always granting it inside a write hierarchy is the documented
intent.

`struct landlock_ruleset_attr` size by ABI: ABI 1–3 → `handled_access_fs` only
(8 bytes); ABI 4–5 → + `handled_access_net` (16); ABI ≥ 6 → + `scoped` (24).
Pass the size matching the probed ABI.

---

## 10. Compat headers (`src/compat/`)

Each file `#include`s the system uapi header if present, then `#ifndef`-defines
every constant and struct we use. Reason: Ubuntu 24.04's `linux/landlock.h`
stops at ABI 4 while the kernel it runs on is ABI 7; constants must come from
us, not the build host. Keep the licence note: uapi constants are
`GPL-2.0 WITH Linux-syscall-note` (user-space use explicitly permitted);
list this in `LICENSE.note`.

`landlock_compat.h`: `struct landlock_ruleset_attr`, `landlock_path_beneath_attr`
(packed), `landlock_net_port_attr`, all `LANDLOCK_ACCESS_FS_*`,
`LANDLOCK_ACCESS_NET_*`, `LANDLOCK_SCOPE_*`, `LANDLOCK_RESTRICT_SELF_LOG_*`,
`LANDLOCK_CREATE_RULESET_VERSION`, rule types, and `__NR_landlock_*` fallbacks
(444, 445, 446 — identical on every architecture since they are asm-generic).

`seccomp_compat.h`: `SECCOMP_SET_MODE_FILTER`, `SECCOMP_FILTER_FLAG_TSYNC|LOG`,
`SECCOMP_RET_*` incl. `KILL_PROCESS` and `LOG`, `struct seccomp_data`,
`AUDIT_ARCH_*`, `X32_SYSCALL_BIT`, `__NR_seccomp` fallback (317 x86_64, 277
aarch64 — only these two; otherwise use the prctl path).

`caps_compat.h`: `CAP_*` names table (`CAP_LAST_CAP` fallback 40),
`_LINUX_CAPABILITY_VERSION_3`, `PR_CAP_AMBIENT*`, `PR_CAPBSET_DROP`.

---

## 11. Threads, fds and other sharp edges

- Landlock: per-thread; seccomp: TSYNC. `confine()` warns if `/proc/self/task`
  has > 1 entry and no TSYNC-equivalent exists for Landlock.
- fds: the forked child inherits every fd. Before restricting, close everything
  except 0/1/2 and the three pipe write ends (`lk_close_from(3, keep, n)` via
  `/proc/self/fd` or `close_range(2)` when available). Otherwise an inherited
  fd to a file outside the allowed hierarchy is a hole (Landlock does not
  revoke already-open fds). This is step 0 of §4 and ships in 0.1.0 (M1), not
  M4: a sandbox with a known hole is not a first release.
- `RLIMIT_NOFILE` low values break R (it opens `.rds` lazily); default 256.
- `RLIMIT_AS` and OpenBLAS: OpenBLAS reserves large virtual areas; prefer
  cgroup `memory.max` when available, and document `OPENBLAS_NUM_THREADS=1`
  for the child.
- `fork()` with threads: only the calling thread survives; OpenBLAS handles
  this via `pthread_atfork`; MKL and some OpenMP runtimes do not. Document.
- Ubuntu ≥ 24.04: unprivileged userns gated by AppArmor. Ship
  `inst/apparmor/landlock` (an `unconfined` profile granting `userns` to
  `/usr/lib/R/bin/exec/R` and `Rscript`) and document the sysctl alternative.
  `status()$userns.works` is the truth.
- Docker/containerd default seccomp profile: allows `landlock_*` and `seccomp`
  syscalls; blocks `unshare` with `CLONE_NEWUSER` unless the container is
  privileged or has `--security-opt seccomp=unconfined`. So in pods: Landlock,
  seccomp, caps, rlimits work; namespaces and cgroup limits usually don't.
  `status()` reports it; presets stay useful.

---

## 12. Testing

C harness (no R): `cd tests/c && make && ./run`. Each test forks a child,
applies one layer, exercises it, returns a code. Run as root and as `nobody`
(`su` in CI) to cover both. Must pass on this workspace kernel (6.18, ABI 7)
and on a 5.10 kernel (ABI 0 → everything reports "skipped").

testthat (edition 3; `Config/testthat/parallel` stays off because the tests fork):
- `status()` returns the documented shape on any Linux.
- `eval_safe(1+1)` with `policy = NULL` on every platform (incl. macOS CI).
- Landlock tests `skip_if(status()$landlock_abi == 0)`.
- seccomp: `eval_safe(Sys.getpid(), policy = policy() |> syscalls(deny="getppid"))`
  then `getppid()` inside → `EPERM` surfaces as an R error from `system()`? No:
  test with `.Call` of a tiny C helper exported for tests (`landlock:::test_getppid()`).
- Timeout: `eval_safe(Sys.sleep(5), timeout = 1)` errors in ~1 s and leaves no
  zombie: `kill(pid, 0)` returns `ESRCH` (no `ps`, no `/proc`: macOS has neither
  in a form that is portable).
- Pipe-deadlock regression: child writes 1 MiB to stdout.
- Interrupt: SIGINT to the parent during `eval_safe(Sys.sleep(10))` ends the
  child within a second.
- fd hygiene: a file opened outside the allowed hierarchy before `eval_safe()`
  is not readable through the inherited fd number inside.

Rules the suite follows so it can run on CRAN's machines:
- Nothing one-way (`restrict_self`, `seccomp_deny`, `caps_*`, `confine`,
  `setids`, `chroot`) ever runs in the check process, only in a forked child.
  A test that restricts the check process is a bug even when it passes.
- Every timeout in a test is ≤ 2 s; the suite finishes in under a minute.
- Skips are driven by `status()` fields, never by `Sys.info()`.
- Examples for one-way functions run inside `eval_safe()`; the in-session
  form is shown in `\dontrun{}`.

CI matrix: the repo's reusable workflow (`pedrobtz/r-actions`) with the
`runners` input overridden to macOS release, ubuntu release and ubuntu
oldrel-1: its default row `windows-latest` cannot install an `OS_type: unix`
package. The three R-hub containers stay (CRAN's r-devel Linux compilers,
`-std=gnu23 -pedantic`). The runner job executes as a non-root user and the
container job as root, which covers both sides of design §2 without extra
jobs. A separate job builds and runs `tests/c` on `ubuntu-24.04` and in an
`ubuntu:24.04` container. GitHub VM runners allow user namespaces; the
containers do not, which is the 0.2.0 namespace test split.

Coverage: gcov counters flush at process exit and R-level trace counters live
in the child's memory, so with `raise(SIGKILL)` every line executed in the
child reports as uncovered. The badge undercounts; do not gate on it.

Development host: the maintainer's workstation is macOS. Landlock, seccomp and
capabilities only exist in a Linux VM; the dev loop is Docker (OrbStack /
Docker Desktop / colima) with `rocker/r-ver` for R and `ubuntu:24.04` for the
bare C harness. Docker's default seccomp profile allows the `landlock_*` and
`seccomp` syscalls, so M1 and M2 are fully testable in a container provided the
VM kernel boots with the Landlock LSM enabled: `status()` is the check.

---

## 13. DESCRIPTION / packaging

```
Package: landlock
Title: Process Confinement with 'Landlock', 'seccomp' and Capabilities
Version: 0.0.0.9000
Description: Evaluate R expressions or run programs in a kernel-enforced sandbox.
  Builds on 'Landlock' <https://landlock.io/> (filesystem and TCP rules),
  'seccomp-bpf' (system call filters), capability dropping and resource limits,
  without external libraries. Degrades gracefully with a report when a feature
  is unavailable. A superset of the sandboxing functions in the 'unix' package.
License: MIT + file LICENSE
Copyright: file inst/COPYRIGHTS
OS_type: unix
SystemRequirements: Linux kernel >= 5.13 for Landlock; seccomp and capabilities
  need Linux; resource limits and fork work on any Unix-alike
URL: https://pedrobtz.github.io/landlock/, https://github.com/pedrobtz/landlock
BugReports: https://github.com/pedrobtz/landlock/issues
Encoding: UTF-8
Language: en-US
Suggests: testthat (>= 3.0.0), knitr, rmarkdown
```
No Imports. `src/Makevars`: `PKG_CPPFLAGS = -I. -D_GNU_SOURCE`. Expected source
tarball well under 500 KB. Namespaces and cgroups return to Title and
Description when they ship (0.2.0). CRAN wants software names in single quotes
and a reference for the method, hence the quoting and the URL. `inst/COPYRIGHTS`
is CRAN's form of the §10 licence note: it names the Linux kernel uapi headers
the constants come from and their licence (GPL-2.0 WITH Linux-syscall-note,
which permits user-space use); `LICENSE.note` stays for human readers.

---

## 14. Milestones

| M | Deliverable | Definition of done |
|---|---|---|
| M1 | `ll.c`, `lim.c`, `proc.c` (incl. `lk_close_from`), `rglue.c`; `status()`, `restrict_self()`, `rlimit()`, `eval_safe()`, `run()` without pid-ns (policy = fs + net + limits + ids + timeout); presets as R objects | C harness green; `eval_safe(readLines("/etc/passwd"), policy = preset("numeric"))` errors with EACCES; pipe-deadlock and fd-hygiene tests; unix-compat aliases |
| M2 | `sc.c`, `caps.c`; `syscalls()`, `caps()`; presets `dangerous`, `no_exec`, `no_net` | TSYNC install; seccomp test passes as non-root |
| M3 | `ns.c`; `namespaces()`, `mounts()`; `run()` with pid-ns double fork; AppArmor `profile=` | userns + tmpfs `/tmp` in `eval_safe`; AppArmor profile for Ubuntu 24.04 shipped and documented |
| M4 | `cgroup.R`; streaming stdout | memory.max honoured under systemd-run |
| M5 | TOML policies, `read_policy()`, `write_policy()`, `explain()`, `trace()` with audit parsing | `trace()` proposes a `numeric` policy for a `lm()` call |

Release mapping: **0.1.0 = M1 + M2**, submitted to CRAN; stage-by-stage plan
in [roadmap.md](roadmap.md). M3 and M4 form 0.2.0, M5 follows. Everything in
0.1.0 works unprivileged, inside Docker and on CRAN's check machines;
namespaces are the one layer whose behaviour depends on host policy (AppArmor
on Ubuntu ≥ 24.04, Docker's seccomp profile), which is why they wait.
`namespaces()` and `mounts()` are simply absent from 0.1.0 rather than
exported as stubs.

M1 alone is a usable `unix` successor for the two motivating cases (untrusted
installs, plumber evaluating user code).

---

## 15. Relationship to `unix` and AppArmor

- Function names and `eval_safe()` signature are kept; `profile =` is accepted
  and, from M3, implemented without libapparmor by writing
  `changeprofile <name>` to `/proc/self/attr/apparmor/current` (what
  `aa_change_profile()` does internally). Optional layer, applied between steps
  6 and 7; skipped with a report when AppArmor is absent.
- Jeroen Ooms may prefer an upstream PR for M1 (Landlock + rlimit); keep
  `ll.c`/`lim.c`/`proc.c` free of package-specific assumptions so they can be
  dropped into `unix/src/` unchanged.

---

## 16. Naming

Decided: `landlock`. Landlock is the primary mechanism (every other layer is
optional and degrades); naming after the mechanism follows the convention of
`curl`, `openssl`, `sodium`, `ssh` and `RAppArmor`, and puts the package next to
the Rust, Go and Python bindings the Landlock project lists. The DESCRIPTION
Title carries the wider scope (seccomp, namespaces, capabilities).

Consequences in this document: C symbol prefix is `lk_` (so the Landlock module
reads `lk_ll_*`, seccomp `lk_sc_*`, …), the internal header is `src/lk.h`, the
thin Landlock wrapper is `restrict_self()` rather than `landlock()` to avoid
`landlock::landlock()`, and the sub-cgroup is named `landlock-<pid>`.

Availability: no `landlock` package on CRAN or R-universe found at design time;
confirm case-insensitively before the first commit. The crates.io and PyPI
names are taken by the official Rust crate and a Python binding, which does not
matter for a pure-C R package.

---

## 17. Open decisions

1. Name — decided: `landlock` (§16).
2. `eval_safe` + pid namespace — decided: skip; `run()` gets the double fork (M3).
3. In-process `confine()` in a multi-threaded process — decided: error unless `force = TRUE`.
4. Default id map in a userns: keep caller uid (safe, files stay owned) vs 0 (needed for some mounts). Default keep; `namespaces(user = list(uid = 0))` opts in. (0.2.0)
5. stdout capture in RStudio/`callr` contexts where fd 1 is not the console: accept the `parallel` behaviour, or route through `R_WriteConsole` in the child? Accept for v1.
6. Default seccomp action: `errno` (EPERM, debuggable) vs `kill` (safer). Default `errno`; presets for services use `kill`.
7. Whether `fs(write=)` implies `read`. Decided: no; `fs(rw=)` convenience added.
8. Whether to ship an AppArmor `userns` profile in `inst/` or only document it. Ship it; installation is manual (`sudo cp`), as RAppArmor did. (0.2.0)
9. How the forked child ends — decided: close pipes and `raise(SIGKILL)`, as `unix` does, so compiled code references no `_exit`/`exit` symbol and the first submission carries no compiled-code NOTE. Parent discriminates on the result pipe (§6.3).
10. `eval_safe()` signature — decided: `unix`'s argument list verbatim plus `policy = NULL` appended (§6.2). The earlier draft with `policy` second broke positional compatibility.
11. fd hygiene — decided: M1, not M4 (§11).
