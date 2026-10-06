/* landlock C core: internal API shared by ll.c, lim.c, proc.c (and later
 * sc.c, caps.c) and the R adapter rglue.c. No R headers here (design.md
 * section 3): these files build and test without R, and stay free of package
 * assumptions so they could be dropped into another code base unchanged.
 *
 * Conventions: return 0 on success and -errno on failure; functions that
 * return a value return >= 0 on success and -errno otherwise. No fprintf,
 * no exit, no _exit, no globals except the syscall table. Every entry point
 * is declared on every platform; Linux-only ones return "absent" (0) or
 * -ENOSYS elsewhere.
 */
#ifndef LK_H
#define LK_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* ---- Landlock (ll.c) ------------------------------------------------- */

/* Landlock ABI version: > 0 the ABI, 0 unavailable (ENOSYS, or EOPNOTSUPP
 * when the LSM is disabled at boot), < 0 -errno for anything else. */
int lk_ll_abi(void);

enum { LK_LL_READ = 1, LK_LL_WRITE = 2, LK_LL_EXEC = 4 };

struct lk_ll_path {
    const char *path;
    unsigned mode;                 /* OR of LK_LL_* */
};

struct lk_ll_policy {
    int handle_fs;                 /* 1: mediate the filesystem; paths below are the allow-list */
    const struct lk_ll_path *paths;
    size_t npaths;
    int handle_net;                /* 1: mediate TCP bind/connect; ports below are the allow-lists */
    const uint16_t *bind_ports;
    size_t nbind;
    const uint16_t *connect_ports;
    size_t nconnect;
    int scope_signal;              /* 1: no signals to processes outside the domain (ABI 6) */
    int scope_abstract_unix;       /* 1: no abstract unix sockets outside the domain (ABI 6) */
    unsigned log;                  /* landlock_restrict_self() LOG flags (ABI 7); 0 = kernel default */
    int best_effort;               /* 1: drop what the ABI lacks and report it; 0: -EOPNOTSUPP */
    int force_abi;                 /* testing: > 0 use at most this ABI, -1 act as if absent, 0 probe */
};

struct lk_ll_report {
    int abi;                       /* ABI used */
    int fs, net, scope, log;       /* 1 applied, 0 skipped */
    long failed_path;              /* index into paths when a path failed, else -1 */
};

int lk_ll_restrict(const struct lk_ll_policy *p, struct lk_ll_report *r);

/* Filesystem rights the given ABI knows (the "handled" set); 0 for abi <= 0. */
uint64_t lk_ll_handled_fs(int abi);

/* ---- Limits, ids, priority, chroot, AppArmor (lim.c) ------------------ */

/* "as", "core", "cpu", "data", "fsize", "memlock", "nofile", "nproc",
 * "stack" -> RLIMIT_*; -ENOENT for an unknown name, -ENOTSUP when the
 * platform lacks the resource. */
int lk_rlimit_lookup(const char *name);
int lk_rlimit_get(int res, uint64_t *soft, uint64_t *hard);   /* UINT64_MAX = unlimited */
int lk_rlimit_set(int res, uint64_t soft, uint64_t hard);

/* setgroups (root only), then gid, then uid; (uid_t)-1 / (gid_t)-1 skip. */
int lk_setids(uid_t uid, gid_t gid);

enum { LK_ID_UID = 0, LK_ID_EUID = 1, LK_ID_GID = 2, LK_ID_EGID = 3 };
int lk_setid(int which, unsigned id);      /* setuid / seteuid / setgid / setegid */

int lk_setpgid(pid_t pid, pid_t pgid);
int lk_priority_get(int *prio);
int lk_priority_set(int prio);
int lk_chroot(const char *path);           /* chroot, then chdir("/") */

/* Write "changeprofile <name>" to the AppArmor attribute file. -ENOSYS off
 * Linux; -errno when AppArmor is absent or refuses the profile. */
int lk_aa_change_profile(const char *name);

/* ---- Process plumbing (proc.c) ---------------------------------------- */

pid_t lk_fork(void);                       /* pid, 0 in the child, or -errno */
int lk_pipe(int fds[2]);                   /* both ends close-on-exec */
int lk_dup2(int from, int to);
int lk_set_nonblock(int fd);
int lk_write_all(int fd, const void *buf, size_t len);
int lk_devnull_stdin(void);                /* /dev/null on fd 0 */

/* Close every fd >= lowfd except those in keep. close_range(2) where the
 * kernel has it, else iterate /proc/self/fd or /dev/fd. */
int lk_close_from(int lowfd, const int *keep, size_t nkeep);

struct lk_buf {
    char *data;
    size_t len, cap;
};
void lk_buf_free(struct lk_buf *b);

/* One poll() slice of at most slice_ms. Appends whatever is readable on
 * each fds[i] to bufs[i]; an fd at end-of-file is closed and set to -1.
 * Then reaps pid with WNOHANG; once reaped, drains every remaining fd and
 * sets *done = 1 and *status (waitpid status, or -1 when someone else
 * reaped the child). Returns 0 or -errno. The caller loops, which keeps the
 * core free of R while the R adapter checks for interrupts between slices.
 * Draining while waiting avoids the 64 KiB pipe deadlock. */
int lk_wait_collect(pid_t pid, int *fds, size_t nfds, int slice_ms,
                    struct lk_buf *bufs, int *status, int *done);

int lk_kill(pid_t pid, int sig);

/* Close the given fds, flush stdio, then raise(SIGKILL). Never returns.
 * Used instead of _exit(), which R CMD check flags in package code. */
void lk_child_exit(const int *fds, size_t nfds);

/* 1 if a forked child can unshare(CLONE_NEWUSER), 0 if not, -errno on
 * failure to probe. Always 0 off Linux. */
int lk_userns_works(void);

#endif
