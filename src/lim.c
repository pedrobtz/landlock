/* Resource limits, ids, priority, chroot, AppArmor profile change
 * (design.md section 5.5). Plain POSIX except where marked. */
#include "lk.h"
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>

static const struct { const char *name; int res; } rlimits[] = {
#ifdef RLIMIT_AS
    { "as", RLIMIT_AS },
#endif
    { "core", RLIMIT_CORE },
    { "cpu", RLIMIT_CPU },
    { "data", RLIMIT_DATA },
    { "fsize", RLIMIT_FSIZE },
#ifdef RLIMIT_MEMLOCK
    { "memlock", RLIMIT_MEMLOCK },
#endif
    { "nofile", RLIMIT_NOFILE },
#ifdef RLIMIT_NPROC
    { "nproc", RLIMIT_NPROC },
#endif
    { "stack", RLIMIT_STACK },
#ifdef RLIMIT_RSS
    { "rss", RLIMIT_RSS },
#endif
#ifdef RLIMIT_LOCKS
    { "locks", RLIMIT_LOCKS },
#endif
#ifdef RLIMIT_SIGPENDING
    { "sigpending", RLIMIT_SIGPENDING },
#endif
#ifdef RLIMIT_MSGQUEUE
    { "msgqueue", RLIMIT_MSGQUEUE },
#endif
#ifdef RLIMIT_NICE
    { "nice", RLIMIT_NICE },
#endif
#ifdef RLIMIT_RTPRIO
    { "rtprio", RLIMIT_RTPRIO },
#endif
#ifdef RLIMIT_RTTIME
    { "rttime", RLIMIT_RTTIME },
#endif
};

static const char *known_rlimits[] = {
    "as", "core", "cpu", "data", "fsize", "memlock", "nofile", "nproc", "stack",
    "rss", "locks", "sigpending", "msgqueue", "nice", "rtprio", "rttime"
};

int lk_rlimit_lookup(const char *name)
{
    for (size_t i = 0; i < sizeof rlimits / sizeof rlimits[0]; i++)
        if (strcmp(rlimits[i].name, name) == 0)
            return rlimits[i].res;
    for (size_t i = 0; i < sizeof known_rlimits / sizeof known_rlimits[0]; i++)
        if (strcmp(known_rlimits[i], name) == 0)
            return -ENOTSUP;  /* a real resource this platform lacks */
    return -ENOENT;
}

static uint64_t from_rlim(rlim_t v)
{
    return v == RLIM_INFINITY ? UINT64_MAX : (uint64_t) v;
}

static rlim_t to_rlim(uint64_t v)
{
    if (v == UINT64_MAX || v >= (uint64_t) RLIM_INFINITY)
        return RLIM_INFINITY;
    return (rlim_t) v;
}

int lk_rlimit_get(int res, uint64_t *soft, uint64_t *hard)
{
    struct rlimit lim;
    if (getrlimit(res, &lim) != 0)
        return -errno;
    *soft = from_rlim(lim.rlim_cur);
    *hard = from_rlim(lim.rlim_max);
    return 0;
}

int lk_rlimit_set(int res, uint64_t soft, uint64_t hard)
{
    struct rlimit lim;
    lim.rlim_cur = to_rlim(soft);
    lim.rlim_max = to_rlim(hard);
    if (setrlimit(res, &lim) != 0)
        return -errno;
    return 0;
}

int lk_setids(uid_t uid, gid_t gid)
{
    if (gid != (gid_t) -1) {
        /* Only root can (and needs to) replace the supplementary groups. */
        if (geteuid() == 0 && setgroups(1, &gid) != 0)
            return -errno;
#ifdef __linux__
        if (setresgid(gid, gid, gid) != 0)
            return -errno;
#else
        if (setgid(gid) != 0)
            return -errno;
#endif
    }
    if (uid != (uid_t) -1) {
        if (gid == (gid_t) -1 && geteuid() == 0 && setgroups(0, NULL) != 0)
            return -errno;
#ifdef __linux__
        if (setresuid(uid, uid, uid) != 0)
            return -errno;
#else
        if (setuid(uid) != 0)
            return -errno;
#endif
    }
    return 0;
}

int lk_setid(int which, unsigned id)
{
    int rc;
    switch (which) {
    case LK_ID_UID:  rc = setuid((uid_t) id); break;
    case LK_ID_EUID: rc = seteuid((uid_t) id); break;
    case LK_ID_GID:  rc = setgid((gid_t) id); break;
    case LK_ID_EGID: rc = setegid((gid_t) id); break;
    default: return -EINVAL;
    }
    return rc != 0 ? -errno : 0;
}

int lk_setpgid(pid_t pid, pid_t pgid)
{
    return setpgid(pid, pgid) != 0 ? -errno : 0;
}

int lk_priority_get(int *prio)
{
    errno = 0;
    int p = getpriority(PRIO_PROCESS, 0);
    if (p == -1 && errno != 0)
        return -errno;
    *prio = p;
    return 0;
}

int lk_priority_set(int prio)
{
    return setpriority(PRIO_PROCESS, 0, prio) != 0 ? -errno : 0;
}

int lk_chroot(const char *path)
{
    if (chroot(path) != 0)
        return -errno;
    if (chdir("/") != 0)
        return -errno;
    return 0;
}

int lk_aa_change_profile(const char *name)
{
#ifdef __linux__
    char buf[4096];
    int n = snprintf(buf, sizeof buf, "changeprofile %s", name);
    if (n < 0 || (size_t) n >= sizeof buf)
        return -ENAMETOOLONG;
    /* The AppArmor-specific file exists on kernels with LSM stacking; the
     * generic one is AppArmor's only when it is the primary LSM, which the
     * caller establishes before falling back to it. */
    int fd = open("/proc/self/attr/apparmor/current", O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        fd = open("/proc/self/attr/current", O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -errno;
    ssize_t w = write(fd, buf, (size_t) n);
    int e = errno;
    close(fd);
    if (w < 0)
        return -e;
    if (w != n)
        return -EIO;
    return 0;
#else
    (void) name;
    return -ENOSYS;
#endif
}
