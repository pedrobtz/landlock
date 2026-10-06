/* Capabilities and no_new_privs (design.md section 5.3). */
#include "lk.h"
#include <errno.h>

#ifdef __linux__
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include "compat/caps_compat.h"

int lk_cap_last(void)
{
    FILE *f = fopen("/proc/sys/kernel/cap_last_cap", "r");
    int last = -1;
    if (f) {
        if (fscanf(f, "%d", &last) != 1)
            last = -1;
        fclose(f);
    }
    if (last < 0 || last > 63)
        last = LK_CAP_LAST_CAP_FALLBACK;
    return last;
}

static int kept(int cap, const int *keep, size_t nkeep)
{
    for (size_t i = 0; i < nkeep; i++)
        if (keep[i] == cap)
            return 1;
    return 0;
}

int lk_caps_drop_bounding(const int *keep, size_t nkeep)
{
    int last = lk_cap_last();
    for (int cap = 0; cap <= last; cap++) {
        if (kept(cap, keep, nkeep))
            continue;
        int in = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
        if (in < 0) {
            if (errno == EINVAL)
                continue;  /* the kernel does not know this capability */
            return -errno;
        }
        if (in == 1 && prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0)
            return -errno;
    }
    return 0;
}

int lk_caps_clear(const int *keep, size_t nkeep)
{
    struct lk_cap_header hdr = { LK_LINUX_CAPABILITY_VERSION_3, 0 };
    struct lk_cap_data data[2];
    memset(data, 0, sizeof data);
    if (syscall(SYS_capget, &hdr, data) != 0)
        return -errno;
    uint32_t mask[2] = { 0, 0 };
    for (size_t i = 0; i < nkeep; i++)
        if (keep[i] >= 0 && keep[i] < 64)
            mask[keep[i] / 32] |= 1U << (keep[i] % 32);
    for (int w = 0; w < 2; w++) {
        data[w].permitted &= mask[w];
        data[w].effective = data[w].permitted;
        data[w].inheritable &= data[w].permitted;
    }
    hdr.version = LK_LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;
    if (syscall(SYS_capset, &hdr, data) != 0)
        return -errno;
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 && errno != EINVAL)
        return -errno;  /* EINVAL: kernel before 4.3, no ambient set */
    return 0;
}

int lk_nnp_set(void)
{
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ? -errno : 0;
}

int lk_mdwe_set(void)
{
    /* -EINVAL before Linux 6.3, which lacks PR_SET_MDWE. */
    return prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0) != 0 ? -errno : 0;
}

int lk_nnp_get(void)
{
    int r = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    return r < 0 ? -errno : r;
}

#else /* not Linux */

int lk_cap_last(void)
{
    return -ENOSYS;
}

int lk_caps_drop_bounding(const int *keep, size_t nkeep)
{
    (void) keep; (void) nkeep;
    return -ENOSYS;
}

int lk_caps_clear(const int *keep, size_t nkeep)
{
    (void) keep; (void) nkeep;
    return -ENOSYS;
}

int lk_nnp_set(void)
{
    return -ENOSYS;
}

int lk_mdwe_set(void)
{
    return -ENOSYS;
}

int lk_nnp_get(void)
{
    return 0;
}

#endif
