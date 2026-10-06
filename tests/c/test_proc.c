/* Process plumbing core tests. */
#include "harness.h"
#include "lk.h"

#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>

static double now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double) ts.tv_sec + (double) ts.tv_nsec / 1e9;
}

/* Fork a child that writes `len` bytes of 'a' then ends with lk_child_exit. */
static pid_t writer(int fds[2], size_t len)
{
    if (lk_pipe(fds) != 0)
        return -1;
    pid_t pid = lk_fork();
    if (pid == 0) {
        close(fds[0]);
        char block[4096];
        memset(block, 'a', sizeof block);
        while (len > 0) {
            size_t n = len < sizeof block ? len : sizeof block;
            if (lk_write_all(fds[1], block, n) != 0)
                break;
            len -= n;
        }
        lk_child_exit(&fds[1], 1);
    }
    close(fds[1]);
    lk_set_nonblock(fds[0]);
    return pid;
}

static int collect(pid_t pid, int fd, struct lk_buf *b, int *status, double limit)
{
    int fds[1] = { fd };
    int done = 0;
    double t0 = now();
    while (!done) {
        int rc = lk_wait_collect(pid, fds, 1, 50, b, status, &done);
        if (rc != 0)
            return rc;
        if (now() - t0 > limit)
            return -ETIMEDOUT;
    }
    if (fds[0] >= 0)
        close(fds[0]);
    return 0;
}

LK_TEST(small_payload)
{
    int fds[2];
    pid_t pid = writer(fds, 5);
    CHECK(pid > 0, "fork");
    struct lk_buf b = { NULL, 0, 0 };
    int status = 0;
    int rc = collect(pid, fds[0], &b, &status, 10);
    CHECK(rc == 0, "collect: %s", strerror(-rc));
    CHECK(b.len == 5, "got %zu bytes", b.len);
    CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL, "child did not end by SIGKILL");
    lk_buf_free(&b);
    PASS();
}

LK_TEST(one_mebibyte_no_deadlock)
{
    int fds[2];
    size_t len = 1u << 20;
    pid_t pid = writer(fds, len);
    CHECK(pid > 0, "fork");
    struct lk_buf b = { NULL, 0, 0 };
    int status = 0;
    int rc = collect(pid, fds[0], &b, &status, 20);
    CHECK(rc == 0, "collect: %s", strerror(-rc));
    CHECK(b.len == len, "got %zu of %zu bytes", b.len, len);
    lk_buf_free(&b);
    PASS();
}

LK_TEST(timeout_kill)
{
    int fds[2];
    CHECK(lk_pipe(fds) == 0, "pipe");
    pid_t pid = lk_fork();
    if (pid == 0) {
        close(fds[0]);
        sleep(30);
        lk_child_exit(&fds[1], 1);
    }
    close(fds[1]);
    lk_set_nonblock(fds[0]);
    int pfd[1] = { fds[0] };
    struct lk_buf b = { NULL, 0, 0 };
    int status = 0, done = 0, killed = 0;
    double t0 = now();
    while (!done) {
        int rc = lk_wait_collect(pid, pfd, 1, 50, &b, &status, &done);
        CHECK(rc == 0, "collect: %s", strerror(-rc));
        if (!killed && now() - t0 > 0.3) {
            CHECK(lk_kill(pid, SIGKILL) == 0, "kill");
            killed = 1;
        }
        CHECK(now() - t0 < 10, "child not reaped after kill");
    }
    CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL, "wrong status");
    CHECK(kill(pid, 0) != 0 && errno == ESRCH, "zombie left behind");
    lk_buf_free(&b);
    PASS();
}

LK_TEST(hygiene_replaces_with_devnull)
{
    char path[256];
    snprintf(path, sizeof path, "%s/secret", lk_t_tmpdir());
    int w = open(path, O_CREAT | O_WRONLY, 0600);
    CHECK(w >= 0 && write(w, "secret", 6) == 6, "setup");
    close(w);
    int fds[4];
    for (int i = 0; i < 4; i++) {
        fds[i] = open(path, O_RDONLY);
        CHECK(fds[i] >= 0, "open");
    }
    int keep[] = { fds[1] };
    int rc = lk_fd_hygiene(3, keep, 1);
    CHECK(rc == 0, "hygiene: %s", strerror(-rc));
    for (int i = 0; i < 4; i++) {
        char buf[8];
        ssize_t n = read(fds[i], buf, sizeof buf);
        if (i == 1) {
            CHECK(n == 6, "kept fd lost its file (read %zd)", n);
        } else {
            CHECK(n == 0, "fd %d still reads the file (read %zd)", fds[i], n);
            CHECK(fcntl(fds[i], F_GETFD) & FD_CLOEXEC, "fd %d not close-on-exec", fds[i]);
        }
    }
    /* the numbers stay taken: a new open gets a fresh one */
    int fresh = open("/dev/null", O_RDONLY);
    for (int i = 0; i < 4; i++)
        CHECK(fresh != fds[i], "number %d was reused", fresh);
    PASS();
}

LK_TEST(pipe_is_cloexec)
{
    int fds[2];
    CHECK(lk_pipe(fds) == 0, "pipe");
    CHECK((fcntl(fds[0], F_GETFD) & FD_CLOEXEC) && (fcntl(fds[1], F_GETFD) & FD_CLOEXEC),
          "pipe not close-on-exec");
    PASS();
}

LK_TEST(devnull_stdin)
{
    CHECK(lk_devnull_stdin() == 0, "devnull");
    char c;
    CHECK(read(0, &c, 1) == 0, "stdin not at EOF");
    PASS();
}

LK_TEST(userns_probe)
{
    int r = lk_userns_works();
    CHECK(r == 0 || r == 1, "lk_userns_works() = %d", r);
    snprintf(msg, msglen, "user namespaces %s", r ? "work" : "unavailable");
    return LK_T_PASS;
}

LK_SUITE(suite_proc) = {
    { "small_payload", small_payload },
    { "one_mebibyte_no_deadlock", one_mebibyte_no_deadlock },
    { "timeout_kill", timeout_kill },
    { "hygiene_replaces_with_devnull", hygiene_replaces_with_devnull },
    { "pipe_is_cloexec", pipe_is_cloexec },
    { "devnull_stdin", devnull_stdin },
    { "userns_probe", userns_probe },
    { NULL, NULL }
};
