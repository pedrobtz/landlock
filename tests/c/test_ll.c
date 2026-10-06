/* Landlock core tests. Each runs in its own forked child (harness.h). */
#include "harness.h"
#include "lk.h"

#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#ifdef __linux__
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

static struct lk_ll_policy fs_policy(const struct lk_ll_path *paths, size_t n)
{
    struct lk_ll_policy p;
    memset(&p, 0, sizeof p);
    p.handle_fs = 1;
    p.paths = paths;
    p.npaths = n;
    p.best_effort = 1;
    return p;
}

static int write_file(const char *path)
{
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0)
        return -errno;
    ssize_t w = write(fd, "x", 1);
    close(fd);
    return w == 1 ? 0 : -EIO;
}

LK_TEST(abi_probe)
{
    int abi = lk_ll_abi();
    CHECK(abi >= 0, "lk_ll_abi() = %d", abi);
    PASS();
}

LK_TEST(deny_outside_allow_inside)
{
    if (lk_ll_abi() == 0)
        SKIP("no Landlock");
    struct lk_ll_path paths[] = { { lk_t_tmpdir(), LK_LL_READ | LK_LL_WRITE } };
    struct lk_ll_policy p = fs_policy(paths, 1);
    struct lk_ll_report r;
    int rc = lk_ll_restrict(&p, &r);
    CHECK(rc == 0, "restrict: %s", strerror(-rc));
    CHECK(r.fs == 1 && r.abi > 0, "report fs=%d abi=%d", r.fs, r.abi);

    int fd = open("/etc/passwd", O_RDONLY);
    CHECK(fd < 0 && errno == EACCES, "open /etc/passwd: fd %d errno %d", fd, errno);

    char path[256];
    snprintf(path, sizeof path, "%s/inside", lk_t_tmpdir());
    rc = write_file(path);
    CHECK(rc == 0, "write inside: %s", strerror(-rc));
    PASS();
}

LK_TEST(write_does_not_imply_read)
{
    if (lk_ll_abi() == 0)
        SKIP("no Landlock");
    char path[256];
    snprintf(path, sizeof path, "%s/f", lk_t_tmpdir());
    CHECK(write_file(path) == 0, "setup");
    struct lk_ll_path paths[] = { { lk_t_tmpdir(), LK_LL_WRITE } };
    struct lk_ll_policy p = fs_policy(paths, 1);
    struct lk_ll_report r;
    int rc = lk_ll_restrict(&p, &r);
    CHECK(rc == 0, "restrict: %s", strerror(-rc));
    int fd = open(path, O_RDONLY);
    CHECK(fd < 0 && errno == EACCES, "read allowed with write-only rule");
    fd = open(path, O_WRONLY);
    CHECK(fd >= 0, "write denied: %s", strerror(errno));
    close(fd);
    PASS();
}

LK_TEST(rule_on_a_file)
{
    if (lk_ll_abi() == 0)
        SKIP("no Landlock");
    char file[256], sibling[256];
    snprintf(file, sizeof file, "%s/allowed", lk_t_tmpdir());
    snprintf(sibling, sizeof sibling, "%s/sibling", lk_t_tmpdir());
    CHECK(write_file(file) == 0, "setup");
    /* Every mode on a regular file: directory-only rights must be masked off
     * or the kernel answers EINVAL. */
    struct lk_ll_path paths[] = { { file, LK_LL_READ | LK_LL_WRITE | LK_LL_EXEC } };
    struct lk_ll_policy p = fs_policy(paths, 1);
    struct lk_ll_report r;
    int rc = lk_ll_restrict(&p, &r);
    CHECK(rc == 0, "restrict: %s", strerror(-rc));
    int fd = open(file, O_RDWR);
    CHECK(fd >= 0, "open allowed file: %s", strerror(errno));
    close(fd);
    rc = write_file(sibling);
    CHECK(rc == -EACCES, "create sibling: %s", strerror(-rc));
    PASS();
}

LK_TEST(missing_path_reports_index)
{
    if (lk_ll_abi() == 0)
        SKIP("no Landlock");
    struct lk_ll_path paths[] = {
        { lk_t_tmpdir(), LK_LL_READ },
        { "/nonexistent/landlock-test", LK_LL_READ },
    };
    struct lk_ll_policy p = fs_policy(paths, 2);
    struct lk_ll_report r;
    int rc = lk_ll_restrict(&p, &r);
    CHECK(rc == -ENOENT, "rc %d", rc);
    CHECK(r.failed_path == 1, "failed_path %ld", r.failed_path);
    /* Nothing was enforced: /etc is still readable. */
    int fd = open("/etc/passwd", O_RDONLY);
    CHECK(fd >= 0, "restricted after a failed setup");
    close(fd);
    PASS();
}

LK_TEST(absent_best_effort_and_strict)
{
    struct lk_ll_path paths[] = { { lk_t_tmpdir(), LK_LL_READ } };
    struct lk_ll_policy p = fs_policy(paths, 1);
    p.force_abi = -1;
    struct lk_ll_report r;
    int rc = lk_ll_restrict(&p, &r);
    CHECK(rc == 0 && r.abi == 0 && r.fs == 0, "best effort: rc %d abi %d fs %d", rc, r.abi, r.fs);
    p.best_effort = 0;
    rc = lk_ll_restrict(&p, &r);
    CHECK(rc == -EOPNOTSUPP, "strict: rc %d", rc);
    int fd = open("/etc/passwd", O_RDONLY);
    CHECK(fd >= 0, "restricted although Landlock was treated as absent");
    close(fd);
    PASS();
}

LK_TEST(every_abi_level)
{
    int kabi = lk_ll_abi();
    if (kabi == 0)
        SKIP("no Landlock");
    /* Stack one domain per ABI level the kernel offers: exercises each
     * ruleset attribute size against the real kernel. */
    struct lk_ll_path paths[] = { { "/", LK_LL_READ | LK_LL_WRITE | LK_LL_EXEC } };
    for (int a = 1; a <= kabi && a <= 7; a++) {
        struct lk_ll_policy p = fs_policy(paths, 1);
        p.force_abi = a;
        struct lk_ll_report r;
        int rc = lk_ll_restrict(&p, &r);
        CHECK(rc == 0, "abi %d: %s", a, strerror(-rc));
        CHECK(r.abi == a && r.fs == 1, "abi %d: report abi %d fs %d", a, r.abi, r.fs);
    }
    PASS();
}

LK_TEST(net_unavailable_below_abi4)
{
    if (lk_ll_abi() == 0)
        SKIP("no Landlock");
    struct lk_ll_policy p;
    memset(&p, 0, sizeof p);
    p.handle_net = 1;
    p.force_abi = 3;
    p.best_effort = 0;
    struct lk_ll_report r;
    int rc = lk_ll_restrict(&p, &r);
    CHECK(rc == -EOPNOTSUPP, "strict: rc %d", rc);
    p.best_effort = 1;
    rc = lk_ll_restrict(&p, &r);
    CHECK(rc == 0 && r.net == 0, "best effort: rc %d net %d", rc, r.net);
    PASS();
}

#ifdef __linux__
static int tcp(int do_bind, uint16_t port)
{
    int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0)
        return -errno;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int rc = do_bind ? bind(s, (struct sockaddr *) &a, sizeof a)
                     : connect(s, (struct sockaddr *) &a, sizeof a);
    int e = rc != 0 ? errno : 0;
    close(s);
    return -e;
}
#endif

LK_TEST(tcp_allow_lists)
{
#ifdef __linux__
    if (lk_ll_abi() < 4)
        SKIP("Landlock ABI %d < 4: no TCP rules", lk_ll_abi());
    uint16_t bind_ok[] = { 47613 };
    struct lk_ll_policy p;
    memset(&p, 0, sizeof p);
    p.handle_net = 1;
    p.bind_ports = bind_ok;
    p.nbind = 1;
    struct lk_ll_report r;
    int rc = lk_ll_restrict(&p, &r);
    CHECK(rc == 0 && r.net == 1, "restrict: rc %d net %d", rc, r.net);
    rc = tcp(1, 47614);
    CHECK(rc == -EACCES, "bind to unlisted port: %s", strerror(-rc));
    rc = tcp(1, 47613);
    CHECK(rc == 0 || rc == -EADDRINUSE, "bind to listed port: %s", strerror(-rc));
    rc = tcp(0, 47615);
    CHECK(rc == -EACCES, "connect to unlisted port: %s", strerror(-rc));
    PASS();
#else
    SKIP("not Linux");
#endif
}

LK_TEST(scope_signal)
{
    if (lk_ll_abi() < 6)
        SKIP("Landlock ABI %d < 6: no scopes", lk_ll_abi());
    struct lk_ll_policy p;
    memset(&p, 0, sizeof p);
    p.scope_signal = 1;
    struct lk_ll_report r;
    int rc = lk_ll_restrict(&p, &r);
    CHECK(rc == 0 && r.scope == 1, "restrict: rc %d scope %d", rc, r.scope);
    CHECK(kill(getppid(), 0) != 0 && errno == EPERM, "signal to parent allowed");
    CHECK(kill(getpid(), 0) == 0, "signal to self denied");
    PASS();
}

LK_TEST(nothing_requested_is_noop)
{
    struct lk_ll_policy p;
    memset(&p, 0, sizeof p);
    struct lk_ll_report r;
    int rc = lk_ll_restrict(&p, &r);
    CHECK(rc == 0 && r.fs == 0 && r.net == 0 && r.scope == 0, "rc %d", rc);
    PASS();
}

LK_SUITE(suite_ll) = {
    { "abi_probe", abi_probe },
    { "deny_outside_allow_inside", deny_outside_allow_inside },
    { "write_does_not_imply_read", write_does_not_imply_read },
    { "rule_on_a_file", rule_on_a_file },
    { "missing_path_reports_index", missing_path_reports_index },
    { "absent_best_effort_and_strict", absent_best_effort_and_strict },
    { "every_abi_level", every_abi_level },
    { "net_unavailable_below_abi4", net_unavailable_below_abi4 },
    { "tcp_allow_lists", tcp_allow_lists },
    { "scope_signal", scope_signal },
    { "nothing_requested_is_noop", nothing_requested_is_noop },
    { NULL, NULL }
};
