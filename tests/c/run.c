/* Test runner for the landlock C core. Not part of the R package: it may use
 * printf and exit freely. */
#include "harness.h"
#include "suites.h"
#include "lk.h"

#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#define LK_DECLARE(s) extern const struct lk_test s[];
LK_SUITE_LIST(LK_DECLARE)

#define LK_ENTRY(s) { #s, s },
static const struct { const char *name; const struct lk_test *tests; } suites[] = {
    LK_SUITE_LIST(LK_ENTRY)
    { NULL, NULL }
};

static char tmpdir[64];

const char *lk_t_tmpdir(void)
{
    return tmpdir;
}

static int run_one(const struct lk_test *t, char *msg, size_t msglen)
{
    int fds[2];
    if (pipe(fds) != 0) {
        snprintf(msg, msglen, "pipe: %s", strerror(errno));
        return LK_T_FAIL;
    }
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) {
        snprintf(msg, msglen, "fork: %s", strerror(errno));
        return LK_T_FAIL;
    }
    if (pid == 0) {
        close(fds[0]);
        snprintf(tmpdir, sizeof tmpdir, "/tmp/lk-test-XXXXXX");
        if (mkdtemp(tmpdir) == NULL)
            tmpdir[0] = '\0';
        char buf[512] = "";
        int rc = t->fn(buf, sizeof buf);
        ssize_t n = write(fds[1], buf, strlen(buf));
        (void) n;
        close(fds[1]);
        _exit(rc);
    }
    close(fds[1]);
    size_t len = 0;
    ssize_t n;
    while (len + 1 < msglen && (n = read(fds[0], msg + len, msglen - 1 - len)) > 0)
        len += (size_t) n;
    msg[len] = '\0';
    close(fds[0]);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
        ;
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    snprintf(msg + len, msglen - len, "%schild died with signal %d",
             len ? "; " : "", WIFSIGNALED(status) ? WTERMSIG(status) : -1);
    return LK_T_FAIL;
}

int main(int argc, char **argv)
{
    const char *only = argc > 1 ? argv[1] : NULL;
    int npass = 0, nfail = 0, nskip = 0;

    printf("landlock abi: %d, uid %d, euid %d\n", lk_ll_abi(), (int) getuid(), (int) geteuid());
    for (size_t s = 0; suites[s].name; s++) {
        for (const struct lk_test *t = suites[s].tests; t->name; t++) {
            if (only && !strstr(t->name, only))
                continue;
            char msg[1024] = "";
            int rc = run_one(t, msg, sizeof msg);
            const char *tag = rc == LK_T_PASS ? "ok  " : rc == LK_T_SKIP ? "skip" : "FAIL";
            printf("%s %s/%s%s%s\n", tag, suites[s].name, t->name, msg[0] ? ": " : "", msg);
            if (rc == LK_T_PASS) npass++;
            else if (rc == LK_T_SKIP) nskip++;
            else nfail++;
        }
    }
    printf("%d passed, %d failed, %d skipped\n", npass, nfail, nskip);
    return nfail ? 1 : 0;
}
