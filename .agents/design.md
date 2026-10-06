# landlock — process confinement for R, in pure C

Package name: `landlock` — named after its core mechanism, the way `curl`,
`openssl`, `sodium` and `RAppArmor` are (see §16). **The replacement for the
`unix` package**: every function `unix` 1.6.0 exports exists here with the same
name, arguments and behaviour (§15), so `library(landlock)` is a drop-in for
`library(unix)`. On top of that model — fork-then-restrict, one-way operations,
result serialised back, timeout enforced by the parent — it adds the kernel
features that did not exist in 2013: Landlock, seccomp-bpf, user/mount/net/pid
namespaces, capabilities, cgroup v2.

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
6. Drop-in for `unix`. The 32 exports of `unix` 1.6.0 are part of the public
   API from 0.1.0, with `unix`'s own test suite ported and passing (§15). A
   user who replaces `unix` with `landlock` and changes nothing else must see
   no difference; the new layers are opt-in through `policy`.

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
│   ├── limits.R           rlimit_*(cur, max) family, rlimit_all(), setids(), chroot()   (unix signatures)
│   ├── process.R          getpid(), getppid(), getpgid(), setpgid(), kill(), getpriority(), setpriority(), sys_config()
│   ├── ids.R              getuid()/setuid(), geteuid()/seteuid(), getgid()/setgid(), getegid()/setegid(), user_info(), group_info()
│   ├── apparmor.R         aa_config(), aa_change_profile() through /proc, no libapparmor
│   ├── eval_safe.R        eval_safe(), eval_fork(), run()
│   └── presets.R          preset(): syscall sets and policy presets as R objects
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
│   ├── lim.c              rlimit, ids (set*uid/gid, pwd/grp lookup), priority, chroot, apparmor /proc write
│   ├── proc.c             fork, pipes, fd hygiene, poll-collect wait, child exit, kill
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
 6a. apparmor     changeprofile through /proc                       (§15)
 7. landlock      create ruleset, add rules, no_new_privs, restrict_self
 8. caps bounding drop the bounding set                             (needs CAP_SETPCAP, still effective here)
 9. no_new_privs  prctl (idempotent; also done inside 7 and 10)
10. seccomp       install filter with TSYNC
11. setids        setgroups, setresgid, setresuid                   (needs CAP_SETUID/SETGID, still effective here)
12. caps sets     capset: effective/permitted/inheritable := keep; ambient cleared; no_new_privs
13. rlimits       setrlimit each, as ceilings
14. eval / exec
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
- Capabilities are split around `setids`. The bounding set needs
  `CAP_SETPCAP`, so it goes before anything clears the sets; clearing the
  sets removes `CAP_SETUID`, so it goes after `setids`. Clearing everything
  before `setids` (the first draft) left root unable to switch user. The
  filter must therefore allow `capset`; presets never deny it.
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
    int handle_fs;                     /* 1 = mediate the filesystem; paths are the allow-list */
    const struct lk_ll_path *paths;  size_t npaths;
    int handle_net;                    /* 1 = mediate TCP; allow-lists below   */
    const uint16_t *bind_ports;        size_t nbind;
    const uint16_t *connect_ports;     size_t nconnect;
    int scope_signal, scope_abstract_unix;
    unsigned log;                      /* restrict_self LOG flags (ABI 7), 0 = kernel default */
    int best_effort;                   /* 1: mask to ABI; 0: -EOPNOTSUPP if anything unsupported */
    int force_abi;                     /* testing: >0 use at most this ABI, -1 act as absent, 0 probe */
};

struct lk_ll_report { int abi; int fs; int net; int scope; int log; long failed_path; };

int lk_ll_restrict(const struct lk_ll_policy *p, struct lk_ll_report *r);
uint64_t lk_ll_handled_fs(int abi);
```

`handle_fs` is separate from `npaths` so that `policy() |> net()` without
`fs()` mediates TCP only and leaves the filesystem alone, while `fs()` with no
paths denies the whole filesystem. `force_abi` lets the harness and the R tests
exercise every ruleset size and the "absent" path on a kernel that offers ABI 7;
a kernel accepts rulesets written for any older ABI. `failed_path` is the index
of the path whose rule failed, so the R error can name it.

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

Syscall table: 242 names (`tools/syscalls.txt`). Each entry is
`#ifdef SYS_<name>`-guarded with an `#else` giving `-1`, so every name is
known everywhere and the numbers are exactly the build architecture's, with
no hand-maintained numbers. A name with `-1` (for example `open` on aarch64)
is skipped and reported, a name not in the list at all is an error. The same
generator writes `R/syscall-names.R`, so a policy naming system calls can be
built and validated on macOS too
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
chosen at compile time from `__x86_64__`, `__i386__`, `__aarch64__`, `__arm__`,
`__riscv` (64-bit), `__powerpc64__` (little-endian), `__s390x__`,
`__loongarch64`. The BPF structs and opcodes come from `seccomp_compat.h`
under `lk_`/`LK_` names, so `linux/filter.h` is not needed (musl images ship
it only with `linux-headers`). On any other
architecture `lk_sc_deny()` returns `-ENOTSUP` and the layer reports "skipped";
it never compiles to a filter with a wrong or missing arch check. The x32 guard
is emitted only under `__x86_64__`. The `arch` CI workflow (§12) runs the suite
on i386, musl and aarch64, which are exactly the legs where this table, the
syscall numbers in `sc_table.h` and the `__NR_*` fallbacks (§10) differ.

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
int lk_caps_drop_bounding(const int *keep, size_t nkeep); /* PR_CAPBSET_DROP every cap not in keep */
int lk_caps_clear(const int *keep, size_t nkeep);         /* capset v3: permitted/effective/inheritable = keep; ambient cleared */
int lk_nnp_set(void);
int lk_nnp_get(void);                           /* 0/1 */
```
Capability names live in R (`cap_names`, 41 entries, index = number); C
takes numbers, so there is no `lk_cap_lookup()`. The R API is
`caps(p, keep = character())`, `caps_drop_all()`, `caps_keep(...)` and
`no_new_privs()`; without `CAP_SETPCAP` the bounding set stays and the report
says so (an unprivileged process with `no_new_privs` cannot use it anyway).
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
int lk_setid(int which, unsigned id);                   /* LK_ID_UID, EUID, GID, EGID → setuid/seteuid/setgid/setegid (unix API) */
int lk_setpgid(pid_t pid, pid_t pgid);
int lk_priority_get(int *prio);                         /* getpriority(PRIO_PROCESS, 0), errno-safe */
int lk_priority_set(int prio);
int lk_chroot(const char *path);                        /* chroot + chdir("/") */
int lk_aa_change_profile(const char *name);             /* single write(2) of "changeprofile <name>" to /proc/self/attr/apparmor/current, fallback /proc/self/attr/current; -ENOSYS without AppArmor */
```

`user_info()` and `group_info()` (`getpwuid_r`, `getgrgid_r`) live in
`rglue.c`: they build R lists and have no use outside R. `sys_config()` is
pure R over `Sys.info()`, `getpid()` and the rlimit calls.

### 5.6 Process plumbing (`proc.c`)

```c
pid_t lk_fork(void);
int   lk_pipe(int fds[2]);                               /* O_CLOEXEC */
int   lk_dup2(int from, int to);
int   lk_set_nonblock(int fd);
int   lk_write_all(int fd, const void *buf, size_t len);
int   lk_devnull_stdin(void);
int   lk_close_from(int lowfd, const int *keep, size_t nkeep);
/* close_range(2) over the gaps between kept fds where available, else list
   /proc/self/fd (Linux) or /dev/fd (macOS) in batches: no malloc in a fresh child */
struct lk_buf { char *data; size_t len, cap; };
void  lk_buf_free(struct lk_buf *b);
int   lk_wait_collect(pid_t pid, int *fds, size_t nfds, int slice_ms,
                        struct lk_buf *bufs, int *status, int *done);
/* ONE poll() slice of at most slice_ms: drains every readable fd into its buffer
   (an fd at EOF is closed and set to -1), handles EINTR, then waitpid(WNOHANG).
   Once reaped, drains what is left and sets *done and *status (-1 if someone else
   reaped it, e.g. a SIGCHLD handler). Returns 0 or -errno. The caller loops; between
   slices rglue.c calls R_CheckUserInterrupt() and enforces the wall-clock timeout, so
   Ctrl-C works and the core stays free of R. Draining while waiting avoids the 64 KiB
   pipe deadlock. */
int   lk_kill(pid_t pid, int sig);
void  lk_child_exit(const int *fds, size_t nfds);
/* fflush(NULL), close the given fds, then raise(SIGKILL). Never returns. */
int   lk_userns_works(void);
/* forked probe: 1 if unshare(CLONE_NEWUSER) succeeds; the probe child reports
   through a pipe and ends by SIGKILL, never through an exit code */
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
p <- policy(best_effort = TRUE, log = NULL) |>
  fs(read  = c("/usr", "/etc/R", "/etc/ld.so.cache", .libPaths()),
     write = tempdir(),
     exec  = c("/usr/lib/R", "/usr/bin")) |>
  net(bind = integer(), connect = 443) |>     # calling net() at all mediates TCP
  scope(signal = TRUE, abstract_unix = TRUE) |>
  syscalls(deny = c(preset("dangerous"), "execve"), action = "errno") |>   # 0.1.0 Stage 4
  caps(keep = character()) |>                                               # 0.1.0 Stage 4
  limits(memory = "1g", pids = 32, cpu = 60, fsize = "100m", nofile = 256) |>
  ids(uid = NULL, gid = NULL) |>
  apparmor("my-profile")
```

There is no `options()` verb: it would mask `base::options()` for anyone who
attaches the package. Best effort and logging are arguments of `policy()`;
`timeout` belongs to `eval_safe()` and `run()`, not to the policy. Likewise
the M5 `trace()` must be renamed (`trace_policy()`): `base::trace()` exists.
`fs()` has `handle_fs` semantics: `fs()` with no paths denies the whole
filesystem, no `fs()` call leaves it alone. Limits are ceilings: a value
above the current hard limit keeps the hard limit instead of failing.

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
apply_policy(p, strict = !p$best_effort)   # engine; returns lk_report (which layers applied / skipped / why)
last_report()                 # the report of the last eval_safe() / run() / confine() / apply_policy()
confine(p, force = FALSE)     # apply_policy on the current process; errors if multi-threaded unless force (§17.3)
eval_safe(expr, tmp = tempfile("fork"), std_out = stdout(), std_err = stderr(),
          timeout = 0, priority = NULL, uid = NULL, gid = NULL, rlimits = NULL,
          profile = NULL, device = pdf, policy = NULL)
eval_fork(expr, tmp = tempfile("fork"), std_out = stdout(), std_err = stderr(), timeout = 0)
run(cmd, args = character(), policy = NULL, timeout = 0, std_out = TRUE, std_err = TRUE, env = NULL)
                              # list(status, signal, stdout, stderr); TRUE captures into the result

restrict_self(read, write, exec, tcp_bind, tcp_connect, scope = c("signal", "abstract_unix"),
         best_effort = TRUE, log = NULL)
seccomp_deny(syscalls, action = c("errno", "kill", "log", "trap"), errno = "EPERM")
seccomp_status(); syscall_table()
caps_drop_all(); caps_keep(...); no_new_privs()
ns_unshare(user = FALSE, mount = FALSE, pid = FALSE, net = FALSE, ipc = FALSE, uts = FALSE, cgroup = FALSE)
ns_map_ids(uid = getuid(), gid = getgid())
mount_private(); mount_bind(src, dst, readonly = TRUE); mount_tmpfs(dst, size = "64m"); mount_ro(path)
rlimit_as(cur = NULL, max = NULL); rlimit_cpu(); rlimit_core(); rlimit_data(); rlimit_fsize();
rlimit_memlock(); rlimit_nofile(); rlimit_nproc(); rlimit_stack(); rlimit_all()   # unix signatures: NULL = query
setids(uid, gid); chroot(path = getwd()); sethostname(name)
getpid(); getppid(); getpgid(); setpgid(pgid = 0); kill(pid, signal = SIGTERM)   # unix
getpriority(); setpriority(prio); sys_config()                                    # unix
getuid(); geteuid(); getgid(); getegid(); setuid(uid); seteuid(uid); setgid(gid); setegid(gid)  # unix
user_info(uid = getuid()); group_info(gid = getgid())                              # unix
aa_config(); aa_change_profile(profile)                                           # unix (RAppArmor names), /proc only
cgroup_v2(); cgroup_limit(memory = NULL, pids = NULL, cpu = NULL)
trace(expr, policy = NULL)     # M5: run with landlock log + seccomp RET_LOG, parse audit → suggested policy
```

`eval_safe()` keeps `unix::eval_safe()`'s argument list verbatim (checked
against `unix/R/fork.R`: `expr, tmp, std_out, std_err, timeout, priority, uid,
gid, rlimits, profile, device`) and appends `policy` as the last named argument,
so every positional call written for `unix` keeps working. `tmp` is the child's
temp directory as in `unix`; `device` is set in the child; `profile` is applied
in the child by `aa_change_profile()` (a `/proc` write, no libapparmor) and
reports "skipped" when AppArmor is absent, or errors when the named profile is
not loaded, as `unix` does. `rlimits`, `uid`, `gid` and `priority` are merged
into the policy as a convenience.

The `unix` API is not a compatibility shim in a side file: those functions are
the package's own exports, documented and tested as such (§15), living in
`limits.R`, `process.R`, `ids.R` and `apparmor.R`.

### 6.3 `eval_safe` engine

```
parent:  three close-on-exec pipes: result, stdout, stderr; fflush(NULL)
         pid <- fork()
child:   setpgid(0, 0); stdin <- /dev/null; dup2 the pipes onto 1 and 2
         if a policy is given: lk_close_from(3, keep = result fd)       # step 0 of section 4
         R_UnwindProtect(body, cleanup):
           body:    child_prepare(): q() guard, TMPDIR <- tmp, sink() to /dev/fd/1 and /dev/fd/2
                    tryCatch(apply_policy(); withVisible(eval(expr))) -> serialize(list(ok, value | error, report))
                    write a 'P' frame on the result pipe
           cleanup: on any jump out of the body, lk_child_exit()        # never back to the parent's toplevel
         lk_child_exit(): fflush(NULL), close, raise(SIGKILL)
parent:  R_UnwindProtect(loop, cleanup):
           loop:    lk_wait_collect(slice 200 ms); stdout/stderr chunks -> callbacks as they arrive;
                    timeout -> SIGKILL to the child's process group; R_CheckUserInterrupt()
           cleanup: on interrupt (or an error in a callback): SIGKILL, reap, free, keep unwinding
         reap; SIGKILL the process group (grandchildren); parse the result frames in R:
         timed out -> error "timeout reached"; no complete 'P' frame -> error "child process has died
         ... (signal N, name)"; else unserialize, re-raise the condition or return the value
```

Result-pipe frames: a type byte, an 8-byte native `double` length, the bytes.
`P` is the payload; `R` is the report `run()` sends before `exec`; `X` marks
that `run()` reached `exec()`. A truncated frame (the child died mid-write) is
dropped. The frame stream is what tells success from death, never the wait
status: every child ends by SIGKILL.

Child robustness without R internals (the CRAN constraint behind §15's
differences):
- `q()` in the child would run R's cleanup, which deletes the session temp
  directory shared with the parent. `child_prepare()` registers an `onexit`
  finalizer that calls `lk_child_exit()`. Exit finalizers run before the temp
  directory is removed and newest first, so it fires first. Its object must
  stay reachable (such finalizers also run on GC); a grandchild keeps the
  guards it inherited.
- R-level output goes through `sink()` to `/dev/fd/1` and `/dev/fd/2` opened
  with `raw = TRUE` (a pipe makes `file()` warn otherwise, and a warning in
  the child reaches whatever calling handlers the parent had on the stack,
  testthat's reporter included). This also captures output under RStudio,
  whose console the child must not use.
- The report is not attached to the returned value (that would alter the
  value, cannot be put on `NULL`, and mutates environments in place); it is
  kept for `last_report()`.

Notes
- `serialize()` materialises ALTREP vectors, so compact sequences and
  memory-mapped vectors cross the pipe as plain data. Objects holding external
  pointers (connections, DuckDB handles, Rcpp XPtr) come back as null pointers;
  document.
- The child must not touch graphics devices or parent connections; `unix` sets
  `options(device = pdf)`; do the same.
- `std_out = NULL` or `FALSE` discards; connections, files and callbacks
  receive output while the child runs, as in `unix`.
- `parallel::mcfork` precedent for forking an R session: after fork the child
  must never return into the parent's event loop; here `R_UnwindProtect`
  and `lk_child_exit()` guarantee it.

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

The build host's uapi headers are never included for Landlock. Ubuntu
24.04's `linux/landlock.h` stops at ABI 4 while the kernel it runs on is ABI 7,
and the obvious remedy, including the system header and `#ifndef`-defining
what is missing, fails for structs: `struct landlock_ruleset_attr` there lacks
the ABI 6 `scoped` field and cannot be redefined. So every name in the compat
headers carries an `lk_` / `LK_` prefix (`struct lk_landlock_ruleset_attr`,
`LK_FS_READ_FILE`, ...), and only the `__NR_*` syscall numbers are
`#ifndef`-guarded. Keep the licence note: uapi constants are
`GPL-2.0 WITH Linux-syscall-note` (user-space use explicitly permitted);
listed in `inst/COPYRIGHTS` and `LICENSE.note`.

`landlock_compat.h`: the three attribute structs (path-beneath packed), all
filesystem and network rights, `LK_FS_ACCESS_FILE`, scopes, restrict-self log
flags, the version flag, rule types, and `__NR_landlock_*` fallbacks
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

CI is `pedrobtz/r-actions` from the first commit. Every check CRAN runs on a
package with compiled code has a reusable workflow there, so the repo carries
thin callers and no hand-rolled matrix except the one job r-actions cannot
express:

| Caller (`.github/workflows/`) | r-actions workflow | Why it applies here |
|---|---|---|
| `R-CMD-check.yaml` | `r-cmd-check.yml` | `runners` overridden to macOS release, ubuntu release, ubuntu oldrel-1: the default `windows-latest` row cannot install an `OS_type: unix` package. Containers at default: CRAN's r-devel Linux compilers with `-std=gnu23 -pedantic`. |
| `coverage.yaml` | `coverage.yml` with `native: true` | covr badge plus a per-file gcov table for `src/`. Both undercount child-side code (below). |
| `native-checks.yaml` | `sanitizers.yml` (UBSan + ASan), `valgrind.yml`, `lto.yml`, `gctorture.yml`, `rchk.yml`, `analyzers.yml`, `cran-special.yml` | rchk and gctorture for `rglue.c`'s PROTECT discipline; sanitizers, valgrind and `-fanalyzer` for the core's error paths; LTO for `lk.h` drifting from its six translation units; rcnst/rlibro/vnu are CRAN's extra checks. |
| `arch.yaml` | `arch.yml`, weekly and on dispatch | i386 and musl, run without emulation on the x86_64 kernel: legs where the seccomp arch constant, the syscall numbers and the `__NR_*` fallbacks differ (§5.2). Run by hand before each release. aarch64 was dropped from it: under QEMU user-mode emulation seccomp filters are rejected and every process gains an emulator thread. |
| (aarch64) | `ubuntu-24.04-arm` runners | a native aarch64 kernel, as a leg of `R-CMD-check` and of `c-harness`. |
| `c-harness.yaml` | hand-written | Builds and runs `tests/c` without R: on the VM runner as the runner user and as `nobody`, and in an `ubuntu:24.04` container as root with gcc and with `clang -std=gnu23 -pedantic`. |
| `pkgdown.yaml` | r-lib template | r-actions has no pkgdown workflow. |

Not used: `fuzz.yml` and `alloc-failure.yml` target parsers; `vendor.yml` and
`vendor-upstream.yml` guard a vendored library, and `src/compat/` holds
constants, not a library. Revisit `vendor.yml` if the compat headers ever
become copied upstream files.

Pull requests run the `quick` profile (one Linux leg, UBSan only, no valgrind,
gctorture at step 500); pushes to `main` and PRs labelled `full-ci` run
everything. A change that touches only `*.md` at the top level or under a dot
directory (`.agents/`, `.github/`), `_pkgdown.yml` or `pkgdown/` skips the code
jobs. The runner legs execute as a non-root user and the containers as root,
which covers both sides of §2 without extra jobs; GitHub VM runners allow user
namespaces and the containers do not, which is the 0.2.0 namespace test split.

Two consequences for the tests themselves:
- The valgrind, ASan and gctorture legs run the suite 10–50× slower. No test
  asserts a tight wall-clock bound: "errors in about 1 s" is written as
  "errors, and the elapsed time is under 10 s"; the child timeouts that drive
  those tests stay short.
- Coverage: gcov counters flush at process exit and R-level trace counters
  live in the child's memory, so with `raise(SIGKILL)` every line executed in
  the child reports as uncovered in both the badge and the native table. Read
  them, do not gate on them; the C harness is where child-side coverage is
  measured.

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
  is unavailable. A drop-in replacement for the 'unix' package: every function
  it exports is provided with the same name and arguments.
License: MIT + file LICENSE
Copyright: file inst/COPYRIGHTS
OS_type: unix
SystemRequirements: Linux kernel >= 5.13 for Landlock; seccomp and capabilities
  need Linux; resource limits and fork work on any Unix-alike
URL: https://pedrobtz.github.io/landlock/, https://github.com/pedrobtz/landlock
BugReports: https://github.com/pedrobtz/landlock/issues
Encoding: UTF-8
Language: en-US
Depends: R (>= 4.1.0)
Imports: grDevices, tools
Suggests: parallel, testthat (>= 3.0.0), knitr, rmarkdown
```
Imports are base packages only: `tools` for the `SIGTERM` default of
`kill()` and `grDevices` for the `pdf` default of `eval_safe(device =)`, both
needed for formals identical to `unix`. `src/Makevars`: `PKG_CPPFLAGS = -I. -D_GNU_SOURCE`. Expected source
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
| M1 | `ll.c`, `lim.c`, `proc.c` (incl. `lk_close_from`), `rglue.c`; the full `unix` API (§15) incl. `profile=`; `status()`, `restrict_self()`, `eval_safe()`, `run()` without pid-ns (policy = fs + net + limits + ids + timeout); presets as R objects | C harness green; `unix`'s ported test suite green; `eval_safe(readLines("/etc/passwd"), policy = preset("numeric"))` errors with EACCES; pipe-deadlock and fd-hygiene tests |
| M2 | `sc.c`, `caps.c`; `syscalls()`, `caps()`; presets `dangerous`, `no_exec`, `no_net` | TSYNC install; seccomp test passes as non-root |
| M3 | `ns.c`; `namespaces()`, `mounts()`; `run()` with pid-ns double fork | userns + tmpfs `/tmp` in `eval_safe`; AppArmor userns profile for Ubuntu 24.04 shipped and documented |
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

## 15. Replacing `unix`

`landlock` replaces `unix`, it does not wrap it. The parity contract, checked
by a test that holds the list below as a constant (`unix` is not a dependency):

```
aa_config chroot eval_fork eval_safe getegid geteuid getgid getpgid getpid
getppid getpriority getuid group_info kill rlimit_all rlimit_as rlimit_core
rlimit_cpu rlimit_data rlimit_fsize rlimit_memlock rlimit_nofile rlimit_nproc
rlimit_stack setegid seteuid setgid setpgid setpriority setuid sys_config
user_info
```

(`unix` 1.6.0 `NAMESPACE`, 32 exports.) For each: same name, same formals in
the same order with the same defaults, same return shape, same error on
failure. `rlimit_*(cur = NULL, max = NULL)` query when both are `NULL` and set
otherwise, returning the new limits invisibly as `unix` does; `rlimit_all()`
returns the named list. `kill(pid, signal = SIGTERM)` takes the signal
constants `unix` exports through `tools::` (`SIGTERM`, `SIGKILL`, ...).

Tests: `unix`'s `tests/testthat/test-forking.R` and `test-process.R` are
ported verbatim (MIT), with `library(unix)` replaced, and must pass on every
CI leg. They are the regression suite for the contract; anything `landlock`
adds is tested separately.

AppArmor without libapparmor: `aa_config()` reads
`/sys/module/apparmor/parameters/enabled` and `/proc/self/attr/apparmor/current`
(fallback `/proc/self/attr/current`); `aa_change_profile(name)` is a single
`write(2)` of `changeprofile <name>` to the same file, which is what
libapparmor's `aa_change_profile()` does internally. `eval_safe(profile=)`
calls it in the child between steps 6 and 7 of §4. Without AppArmor the layer
reports "skipped"; with AppArmor and an unknown profile it errors, as `unix`
does. This is 0.1.0. The shipped `userns` profile (§11) is 0.2.0.

Known differences, forced by CRAN's rule against R internals (`unix` reaches
`R_TempDir`, `R_Interactive` and the console pointers, and enables that code
only when its Makevars detects it is *not* running under `R CMD check`; a new
submission must not copy that):
- `tmp` becomes the child's `TMPDIR`, not its `tempdir()`;
- `interactive()` in the child keeps the session's value (stdin is
  `/dev/null`, so `readline()` returns `""`);
- output is captured with `sink()` rather than by replacing the console.
The ported tests change only the `tempdir()` assertion accordingly.

Migration notes for `unix` users go in the `getting-started` vignette: the
only visible differences are the extra `policy` argument on `eval_safe()`,
the `report` attribute on its result, and a `status()` that says more.

Upstream: Jeroen Ooms may prefer a PR for M1 (Landlock + rlimit); keep
`ll.c`/`lim.c`/`proc.c` free of package-specific assumptions so they can be
dropped into `unix/src/` unchanged. Either outcome is fine; the contract above
holds regardless.

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
12. Relationship to `unix` — decided: full replacement, all 32 exports with identical formals in 0.1.0, `unix`'s tests ported (§15). `profile=` moves from M3 to M1 because it is a `/proc` write.
13. CI — decided: `pedrobtz/r-actions` for everything it covers from the first commit (§12); one hand-written workflow for the no-R C harness; pkgdown stays on the r-lib template.
