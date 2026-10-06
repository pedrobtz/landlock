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
#include <sys/syscall.h>
#ifndef __NR_close_range
#define __NR_close_range 436  /* unified numbering, every architecture */
#endif
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

#ifdef __linux__
/* close_range() over the gaps between kept fds. Returns -ENOSYS when the
 * kernel predates 5.9, so the caller falls back. */
static int close_gaps(int lowfd, const int *keep, size_t nkeep)
{
    int sorted[64];
    size_t n = 0;
    if (nkeep > sizeof sorted / sizeof sorted[0])
        return -ENOSYS;  /* take the directory path */
    for (size_t i = 0; i < nkeep; i++)
        if (keep[i] >= lowfd)
            sorted[n++] = keep[i];
    for (size_t i = 1; i < n; i++)  /* insertion sort, n is tiny */
        for (size_t j = i; j > 0 && sorted[j - 1] > sorted[j]; j--) {
            int t = sorted[j];
            sorted[j] = sorted[j - 1];
            sorted[j - 1] = t;
        }
    /* Close [first, k - 1] before each kept fd k, then [first, ~0]. */
    unsigned first = (unsigned) lowfd;
    for (size_t i = 0; i < n; i++) {
        unsigned k = (unsigned) sorted[i];
        if (k > first && syscall(__NR_close_range, first, k - 1U, 0U) != 0)
            return -errno;
        if (k + 1U > first)
            first = k + 1U;
    }
    if (syscall(__NR_close_range, first, ~0U, 0U) != 0)
        return -errno;
    return 0;
}
#endif

/* Close in passes: collect a batch of fd numbers, close the directory,
 * close the batch, repeat until a pass finds nothing. Closing while
 * iterating would change the directory under readdir(). No malloc: this
 * runs in a freshly forked child. */
static int close_by_listing(const char *dir, int lowfd, const int *keep, size_t nkeep)
{
    for (int pass = 0; pass < 1024; pass++) {
        DIR *d = opendir(dir);
        if (!d)
            return -errno;
        int self = dirfd(d);
        int batch[256];
        size_t n = 0;
        struct dirent *e;
        while (n < sizeof batch / sizeof batch[0] && (e = readdir(d)) != NULL) {
            char *end;
            long v = strtol(e->d_name, &end, 10);
            if (*end != '\0' || end == e->d_name)
                continue;
            int fd = (int) v;
            if (fd < lowfd || fd == self || is_kept(fd, keep, nkeep))
                continue;
            batch[n++] = fd;
        }
        closedir(d);
        if (n == 0)
            return 0;
        for (size_t i = 0; i < n; i++)
            close(batch[i]);
    }
    return -EMFILE;
}

int lk_close_from(int lowfd, const int *keep, size_t nkeep)
{
#ifdef __linux__
    int rc = close_gaps(lowfd, keep, nkeep);
    if (rc != -ENOSYS && rc != -EINVAL)
        return rc;
    return close_by_listing("/proc/self/fd", lowfd, keep, nkeep);
#else
    int rc = close_by_listing("/dev/fd", lowfd, keep, nkeep);
    if (rc == 0)
        return 0;
    long max = sysconf(_SC_OPEN_MAX);
    if (max < 0 || max > 65536)
        max = 65536;
    for (int fd = lowfd; fd < (int) max; fd++)
        if (!is_kept(fd, keep, nkeep))
            close(fd);
    return 0;
#endif
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

    int st = 0;
    pid_t w = waitpid(pid, &st, WNOHANG);
    if (w == 0)
        return 0;
    if (w < 0 && errno == EINTR)
        return 0;
    if (w < 0 && errno != ECHILD)
        return -errno;
    /* Reaped (or reaped by someone else: ECHILD). What the child wrote is
     * in the pipes now; take it. A grandchild may still hold a write end,
     * so stop at "empty for now" rather than waiting for EOF. */
    for (size_t i = 0; i < nfds; i++) {
        if (fds[i] < 0)
            continue;
        int rc = drain(&fds[i], &bufs[i]);
        if (rc < 0)
            return rc;
    }
    *status = w < 0 ? -1 : st;
    *done = 1;
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
