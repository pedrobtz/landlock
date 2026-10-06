/* Limits, ids, priority, chroot, AppArmor core tests. */
#include "harness.h"
#include "lk.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>

LK_TEST(rlimit_names)
{
    const char *names[] = { "core", "cpu", "data", "fsize", "nofile", "stack" };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++)
        CHECK(lk_rlimit_lookup(names[i]) >= 0, "%s unknown", names[i]);
    CHECK(lk_rlimit_lookup("as") >= 0 || lk_rlimit_lookup("as") == -ENOTSUP, "as");
    CHECK(lk_rlimit_lookup("bogus") == -ENOENT, "bogus accepted");
    PASS();
}

LK_TEST(nofile_enforced)
{
    int res = lk_rlimit_lookup("nofile");
    uint64_t soft, hard;
    CHECK(lk_rlimit_get(res, &soft, &hard) == 0, "get");
    int rc = lk_rlimit_set(res, 16, hard);
    CHECK(rc == 0, "set: %s", strerror(-rc));
    CHECK(lk_rlimit_get(res, &soft, &hard) == 0 && soft == 16, "soft now %llu",
          (unsigned long long) soft);
    int last = -1, e = 0;
    for (int i = 0; i < 64; i++) {
        int fd = open("/dev/null", O_RDONLY);
        if (fd < 0) {
            e = errno;
            break;
        }
        last = fd;
    }
    CHECK(e == EMFILE, "open did not fail with EMFILE (errno %d)", e);
    CHECK(last < 16, "fd %d beyond the limit", last);
    PASS();
}

LK_TEST(unlimited_roundtrip)
{
    int res = lk_rlimit_lookup("core");
    uint64_t soft, hard;
    CHECK(lk_rlimit_get(res, &soft, &hard) == 0, "get");
    /* Lowering the soft limit to 0 and back to the hard limit is allowed
     * for anyone. */
    CHECK(lk_rlimit_set(res, 0, hard) == 0, "set 0");
    CHECK(lk_rlimit_set(res, hard, hard) == 0, "set back");
    uint64_t s2, h2;
    CHECK(lk_rlimit_get(res, &s2, &h2) == 0 && s2 == hard && h2 == hard, "roundtrip");
    PASS();
}

LK_TEST(priority)
{
    int p0;
    CHECK(lk_priority_get(&p0) == 0, "get");
    if (p0 >= 19)
        SKIP("already at the lowest priority");
    CHECK(lk_priority_set(p0 + 1) == 0, "set");
    int p1;
    CHECK(lk_priority_get(&p1) == 0 && p1 == p0 + 1, "priority %d, wanted %d", p1, p0 + 1);
    PASS();
}

LK_TEST(setids)
{
    if (geteuid() != 0) {
        int rc = lk_setids(getuid(), getgid());
        CHECK(rc == 0, "own ids: %s", strerror(-rc));
        rc = lk_setids(0, (gid_t) -1);
        CHECK(rc == -EPERM, "became root?: rc %d", rc);
        PASS();
    }
    int rc = lk_setids(65534, 65534);
    CHECK(rc == 0, "setids: %s", strerror(-rc));
    CHECK(getuid() == 65534 && geteuid() == 65534 && getgid() == 65534, "ids not changed");
    gid_t groups[4];
    int n = getgroups(4, groups);
    CHECK(n == 1 && groups[0] == 65534, "supplementary groups not replaced (%d)", n);
    CHECK(lk_setids(0, (gid_t) -1) == -EPERM, "regained root");
    PASS();
}

LK_TEST(setid_same_id)
{
    CHECK(lk_setid(LK_ID_UID, (unsigned) getuid()) == 0, "setuid(getuid())");
    CHECK(lk_setid(LK_ID_GID, (unsigned) getgid()) == 0, "setgid(getgid())");
    CHECK(lk_setid(99, 0) == -EINVAL, "unknown id kind accepted");
    PASS();
}

LK_TEST(chroot_as_root)
{
    if (geteuid() != 0) {
        CHECK(lk_chroot(lk_t_tmpdir()) == -EPERM, "chroot allowed for non-root");
        PASS();
    }
    int rc = lk_chroot(lk_t_tmpdir());
    CHECK(rc == 0, "chroot: %s", strerror(-rc));
    CHECK(access("/etc/passwd", F_OK) != 0, "old root still visible");
    PASS();
}

LK_TEST(apparmor_without_apparmor)
{
    int fd = open("/sys/module/apparmor/parameters/enabled", O_RDONLY);
    if (fd >= 0) {
        char c = 0;
        ssize_t n = read(fd, &c, 1);
        close(fd);
        if (n == 1 && c == 'Y')
            SKIP("AppArmor enabled: covered by the R tests");
    }
    CHECK(lk_aa_change_profile("landlock-test") < 0, "profile change succeeded without AppArmor");
    PASS();
}

LK_SUITE(suite_lim) = {
    { "rlimit_names", rlimit_names },
    { "nofile_enforced", nofile_enforced },
    { "unlimited_roundtrip", unlimited_roundtrip },
    { "priority", priority },
    { "setids", setids },
    { "setid_same_id", setid_same_id },
    { "chroot_as_root", chroot_as_root },
    { "apparmor_without_apparmor", apparmor_without_apparmor },
    { NULL, NULL }
};
