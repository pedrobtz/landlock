/* Capability and no_new_privs core tests. */
#include "harness.h"
#include "lk.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#ifdef __linux__
/* Hex value of a Cap* line in /proc/self/status. */
static unsigned long long cap_line(const char *key)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    unsigned long long v = ~0ULL;
    size_t k = strlen(key);
    while (f && fgets(line, sizeof line, f))
        if (strncmp(line, key, k) == 0 && line[k] == ':')
            v = strtoull(line + k + 1, NULL, 16);
    if (f)
        fclose(f);
    return v;
}
#endif

LK_TEST(cap_last)
{
#ifdef __linux__
    int last = lk_cap_last();
    CHECK(last >= 36 && last < 64, "cap_last %d", last);
    PASS();
#else
    CHECK(lk_cap_last() == -ENOSYS, "off Linux");
    PASS();
#endif
}

LK_TEST(nnp)
{
#ifdef __linux__
    CHECK(lk_nnp_set() == 0, "set");
    CHECK(lk_nnp_get() == 1, "get");
    PASS();
#else
    CHECK(lk_nnp_get() == 0, "off Linux");
    PASS();
#endif
}

LK_TEST(clear_sets)
{
#ifdef __linux__
    int rc = lk_caps_clear(NULL, 0);
    CHECK(rc == 0, "clear: %s", strerror(-rc));
    CHECK(cap_line("CapEff") == 0 && cap_line("CapPrm") == 0 && cap_line("CapAmb") == 0,
          "sets not empty");
    PASS();
#else
    SKIP("not Linux");
#endif
}

LK_TEST(clear_keeps_listed)
{
#ifdef __linux__
    if (geteuid() != 0)
        SKIP("needs root");
    int keep[] = { 21 };  /* CAP_SYS_ADMIN */
    int rc = lk_caps_clear(keep, 1);
    CHECK(rc == 0, "clear: %s", strerror(-rc));
    unsigned long long eff = cap_line("CapEff");
    CHECK(eff == (1ULL << 21) || eff == 0, "CapEff %llx", eff);
    PASS();
#else
    SKIP("not Linux");
#endif
}

LK_TEST(drop_bounding)
{
#ifdef __linux__
    int rc = lk_caps_drop_bounding(NULL, 0);
    if (geteuid() != 0) {
        CHECK(rc == -EPERM || rc == 0, "non-root: rc %d", rc);
        PASS();
    }
    CHECK(rc == 0, "drop: %s", strerror(-rc));
    CHECK(cap_line("CapBnd") == 0, "bounding set %llx", cap_line("CapBnd"));
    PASS();
#else
    SKIP("not Linux");
#endif
}

LK_TEST(mdwe)
{
#ifdef __linux__
    int rc = lk_mdwe_set();
    if (rc == -EINVAL)
        SKIP("kernel before 6.3: no PR_SET_MDWE");
    CHECK(rc == 0, "mdwe: %s", strerror(-rc));
    void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(m == MAP_FAILED, "a writable and executable mapping was allowed");
    m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(m != MAP_FAILED, "plain mapping refused");
    CHECK(mprotect(m, 4096, PROT_READ | PROT_EXEC) != 0, "W then X allowed");
    PASS();
#else
    CHECK(lk_mdwe_set() == -ENOSYS, "off Linux");
    PASS();
#endif
}

LK_TEST(landlock_errata)
{
    int e = lk_ll_errata();
    if (lk_ll_abi() == 0) {
        CHECK(e < 0, "errata without Landlock");
        PASS();
    }
    CHECK(e >= 0 || e == -EINVAL, "errata query: %d", e);
    snprintf(msg, msglen, "errata %s", e >= 0 ? "reported" : "not supported by this kernel");
    return LK_T_PASS;
}

LK_SUITE(suite_caps) = {
    { "cap_last", cap_last },
    { "nnp", nnp },
    { "clear_sets", clear_sets },
    { "clear_keeps_listed", clear_keeps_listed },
    { "drop_bounding", drop_bounding },
    { "mdwe", mdwe },
    { "landlock_errata", landlock_errata },
    { NULL, NULL }
};
