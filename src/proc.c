/* Process plumbing (design.md section 5.6): fork, pipes, fd hygiene, the
 * sliced collect loop, and the child's exit. Plain POSIX except where
 * marked. */
#include "lk.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#ifdef __linux__
#include <sched.h>
#include <sys/prctl.h>
#endif

pid_t lk_fork(void)
{
    pid_t pid = fork();
    return pid < 0 ? -errno : pid;
}

int lk_pipe(int fds[2])
{
#ifdef __linux__
    return pipe2(fds, O_CLOEXEC) != 0 ? -errno : 0;
#else
    if (pipe(fds) != 0)
        return -errno;
    if (fcntl(fds[0], F_SETFD, FD_CLOEXEC) != 0 || fcntl(fds[1], F_SETFD, FD_CLOEXEC) != 0) {
        int e = errno;
        close(fds[0]);
        close(fds[1]);
        return -e;
    }
    return 0;
#endif
}

int lk_dup2(int from, int to)
{
    int r;
    do {
        r = dup2(from, to);
    } while (r < 0 && errno == EINTR);
    return r < 0 ? -errno : 0;
}

int lk_set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0)
        return -errno;
    return 0;
}

int lk_write_all(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    while (len > 0) {
        ssize_t w = write(fd, p, len);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -errno;
        }
        p += w;
        len -= (size_t) w;
    }
    return 0;
}

int lk_devnull_stdin(void)
{
    int fd = open("/dev/null", O_RDONLY);
    if (fd < 0)
        return -errno;
    int rc = 0;
    if (fd != 0) {
        rc = lk_dup2(fd, 0);
        close(fd);
    }
    return rc;
}

/* ---- fd hygiene -------------------------------------------------------- */

static int is_kept(int fd, const int *keep, size_t nkeep)
{
    for (size_t i = 0; i < nkeep; i++)
        if (keep[i] == fd)
            return 1;
    return 0;
}

/* Highest open fd number, from a listing of dir; -1 if it cannot be read. */
static int max_listed_fd(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d)
        return -1;
    int max = -1;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        char *end;
        long v = strtol(e->d_name, &end, 10);
        if (*end == '\0' && end != e->d_name && v > max && v < 1L << 30)
            max = (int) v;
    }
    closedir(d);
    return max;
}

int lk_fd_hygiene(int lowfd, const int *keep, size_t nkeep)
{
    /* Inherited descriptors are replaced, not closed. Closing would free
     * their numbers while R objects inherited from the session (open
     * connections, a pdf() device) still refer to them: the child's next
     * open() would get such a number and a stale write would land in the
     * wrong file. Pointing each at /dev/null keeps the number taken, makes
     * stale writes harmless, and takes the original file out of reach,
     * which is the point: Landlock does not revoke open files. */
    int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null_fd < 0)
        return -errno;
#ifdef __linux__
    int max = max_listed_fd("/proc/self/fd");
#else
    int max = max_listed_fd("/dev/fd");
#endif
    if (max < 0) {
        long lim = sysconf(_SC_OPEN_MAX);
        max = lim < 0 || lim > 65536 ? 65535 : (int) lim - 1;
    }
    int rc = 0;
    for (int fd = lowfd; fd <= max; fd++) {
        if (fd == null_fd || is_kept(fd, keep, nkeep))
            continue;
        if (fcntl(fd, F_GETFD) == -1)
            continue;  /* not open */
        if (lk_dup2(null_fd, fd) == 0) {
            if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
                rc = -errno;
                break;
            }
            continue;
        }
        /* dup2() refuses a number at or above the soft RLIMIT_NOFILE, which
         * an fd opened before the limit was lowered can have. Close it
         * instead: above the limit, open() can never reuse the number. If
         * close() fails with EBADF too, the fd is not this process's to use
         * (valgrind keeps its own there), so there is nothing to protect. */
        if (close(fd) != 0 && errno != EBADF) {
            rc = -errno;
            break;
        }
    }
    close(null_fd);
    return rc;
}

/* ---- collect loop ------------------------------------------------------ */

void lk_buf_free(struct lk_buf *b)
{
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

static int buf_reserve(struct lk_buf *b, size_t extra)
{
    if (b->cap - b->len >= extra)
        return 0;
    size_t cap = b->cap ? b->cap : 65536;
    while (cap - b->len < extra) {
        if (cap > ((size_t) -1) / 2)
            return -ENOMEM;
        cap *= 2;
    }
    char *p = realloc(b->data, cap);
    if (!p)
        return -ENOMEM;
    b->data = p;
    b->cap = cap;
    return 0;
}

/* Read everything currently available. 1 at end-of-file (fd closed and set
 * to -1), 0 when the pipe is empty for now, -errno on error. */
static int drain(int *fd, struct lk_buf *b)
{
    for (;;) {
        int rc = buf_reserve(b, 65536);
        if (rc != 0)
            return rc;
        ssize_t n = read(*fd, b->data + b->len, b->cap - b->len);
        if (n > 0) {
            b->len += (size_t) n;
            continue;
        }
        if (n == 0) {
            close(*fd);
            *fd = -1;
            return 1;
        }
        if (errno == EINTR)
            continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        return -errno;
    }
}

int lk_wait_collect(pid_t pid, int *fds, size_t nfds, int slice_ms,
                    struct lk_buf *bufs, int *status, int *done)
{
    struct pollfd pfd[8];
    size_t map[8];
    size_t np = 0;
    *done = 0;
    if (nfds > 8)
        return -EINVAL;
    for (size_t i = 0; i < nfds; i++) {
        if (fds[i] < 0)
            continue;
        pfd[np].fd = fds[i];
        pfd[np].events = POLLIN;
        pfd[np].revents = 0;
        map[np++] = i;
    }
    /* With every pipe at EOF the child is about to die: poll briefly. */
    int r = poll(np ? pfd : NULL, (nfds_t) np, np ? slice_ms : (slice_ms < 10 ? slice_ms : 10));
    if (r < 0 && errno != EINTR)
        return -errno;
    for (size_t k = 0; r > 0 && k < np; k++) {
        if (!pfd[k].revents)
            continue;
        int rc = drain(&fds[map[k]], &bufs[map[k]]);
        if (rc < 0)
            return rc;
    }

    /* Has the child exited? Ask without reaping: while the exited child is
     * a zombie it pins its pid and process-group id, so the group can be
     * killed (stray grandchildren) without any risk of hitting a process
     * that reused the number. Then reap. */
    siginfo_t info;
    memset(&info, 0, sizeof info);
    if (waitid(P_PID, (id_t) pid, &info, WEXITED | WNOHANG | WNOWAIT) != 0) {
        if (errno == EINTR)
            return 0;
        if (errno != ECHILD)
            return -errno;
        *status = -1;  /* reaped by someone else: the group id may be reused, leave it */
    } else {
        if (info.si_pid == 0)
            return 0;  /* still running */
        kill(-pid, SIGKILL);
        int st = 0;
        pid_t w;
        do {
            w = waitpid(pid, &st, 0);
        } while (w < 0 && errno == EINTR);
        *status = w < 0 ? -1 : st;
    }
    *done = 1;
    /* What the child wrote is in the pipes now; take it. A grandchild may
     * still hold a write end, so stop at "empty for now", not at EOF. */
    for (size_t i = 0; i < nfds; i++) {
        if (fds[i] < 0)
            continue;
        int rc = drain(&fds[i], &bufs[i]);
        if (rc < 0)
            return rc;
    }
    return 0;
}

int lk_kill(pid_t pid, int sig)
{
    return kill(pid, sig) != 0 ? -errno : 0;
}

void lk_child_exit(const int *fds, size_t nfds)
{
    fflush(NULL);  /* NULL rather than stdout: no stdout symbol in the package */
    for (size_t i = 0; i < nfds; i++)
        if (fds[i] >= 0)
            close(fds[i]);
    for (;;)
        raise(SIGKILL);
}

int lk_new_session(void)
{
    return setsid() < 0 ? -errno : 0;
}

int lk_die_with_parent(pid_t parent)
{
#ifdef __linux__
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0)
        return -errno;
    /* The parent may have died between fork() and here: then nothing will
     * deliver the signal, and we must not run on. */
    if (getppid() != parent)
        return -ESRCH;
    return 0;
#else
    (void) parent;
    return -ENOSYS;
#endif
}

int lk_userns_works(void)
{
#ifdef __linux__
    int p[2];
    int rc = lk_pipe(p);
    if (rc != 0)
        return rc;
    pid_t pid = fork();
    if (pid < 0) {
        int e = errno;
        close(p[0]);
        close(p[1]);
        return -e;
    }
    if (pid == 0) {
        char ok = unshare(CLONE_NEWUSER) == 0 ? '1' : '0';
        ssize_t n = write(p[1], &ok, 1);
        (void) n;
        close(p[1]);
        for (;;)
            raise(SIGKILL);
    }
    close(p[1]);
    char c = '0';
    ssize_t n;
    do {
        n = read(p[0], &c, 1);
    } while (n < 0 && errno == EINTR);
    close(p[0]);
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
        ;
    return n == 1 && c == '1';
#else
    return 0;
#endif
}
