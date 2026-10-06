/* seccomp core tests. */
#include "harness.h"
#include "lk.h"

#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif

LK_TEST(table_and_lookup)
{
#ifdef __linux__
    CHECK(lk_sc_count() > 200, "only %zu names", lk_sc_count());
    int nr = lk_sc_lookup("getppid");
    CHECK(nr == SYS_getppid, "getppid = %d", nr);
    CHECK(lk_sc_lookup("no_such_call") == -ENOENT, "unknown name accepted");
#ifdef __aarch64__
    CHECK(lk_sc_lookup("open") == -ENOSYS, "open exists on aarch64?");
#endif
    int seen = 0, absent = 0;
    for (size_t i = 0; i < lk_sc_count(); i++) {
        int n;
        const char *name = lk_sc_name_at(i, &n);
        CHECK(name != NULL, "entry %zu has no name", i);
        if (n >= 0) seen++; else absent++;
    }
    snprintf(msg, msglen, "%d calls on this arch, %d absent", seen, absent);
    return LK_T_PASS;
#else
    CHECK(lk_sc_count() == 0, "table off Linux");
    PASS();
#endif
}

LK_TEST(errno_action)
{
#ifdef __linux__
    int nr = lk_sc_lookup("getppid");
    int tsync = 0;
    int rc = lk_sc_deny(&nr, 1, LK_SC_ERRNO, EPERM, &tsync);
    if (rc == -ENOTSUP)
        SKIP("no seccomp arch entry for this build");
    CHECK(rc == 0, "deny: %s", strerror(-rc));
    CHECK(tsync == 1, "TSYNC not used");
    errno = 0;
    long r = syscall(SYS_getppid);
    CHECK(r == -1 && errno == EPERM, "getppid -> %ld errno %d", r, errno);
    CHECK(getpid() > 0, "getpid broken");
    CHECK(lk_sc_status() == 2, "seccomp mode %d", lk_sc_status());
    PASS();
#else
    int tsync;
    CHECK(lk_sc_deny(NULL, 0, LK_SC_ERRNO, EPERM, &tsync) == -ENOSYS, "off Linux");
    PASS();
#endif
}

LK_TEST(kill_action)
{
#ifdef __linux__
    pid_t pid = fork();
    if (pid == 0) {
        int nr = lk_sc_lookup("getppid");
        int tsync;
        if (lk_sc_deny(&nr, 1, LK_SC_KILL_PROCESS, 0, &tsync) != 0)
            _exit(3);
        syscall(SYS_getppid);
        _exit(0);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    if (WIFEXITED(st) && WEXITSTATUS(st) == 3)
        SKIP("filter not installed");
    CHECK(WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS, "child status %d", st);
    PASS();
#else
    SKIP("not Linux");
#endif
}

LK_TEST(stacked_filters)
{
#ifdef __linux__
    /* Two calls every architecture has (aarch64 has no getpgrp). */
    int a = lk_sc_lookup("getppid"), b = lk_sc_lookup("gettid");
    int tsync;
    CHECK(a >= 0 && b >= 0, "lookup");
    CHECK(lk_sc_deny(&a, 1, LK_SC_ERRNO, EACCES, &tsync) == 0, "first");
    CHECK(lk_sc_deny(&b, 1, LK_SC_ERRNO, EPERM, &tsync) == 0, "second");
    errno = 0;
    CHECK(syscall(SYS_getppid) == -1 && errno == EACCES, "first filter lost");
    errno = 0;
    CHECK(syscall(SYS_gettid) == -1 && errno == EPERM, "second filter missing");
    PASS();
#else
    SKIP("not Linux");
#endif
}

LK_TEST(too_many)
{
#ifdef __linux__
    static int nrs[3000];
    for (int i = 0; i < 3000; i++)
        nrs[i] = 100000 + i;
    int tsync;
    int rc = lk_sc_deny(nrs, 3000, LK_SC_ERRNO, EPERM, &tsync);
    CHECK(rc == -E2BIG || rc == -ENOTSUP, "rc %d", rc);
    PASS();
#else
    SKIP("not Linux");
#endif
}

LK_SUITE(suite_sc) = {
    { "table_and_lookup", table_and_lookup },
    { "errno_action", errno_action },
    { "kill_action", kill_action },
    { "stacked_filters", stacked_filters },
    { "too_many", too_many },
    { NULL, NULL }
};
