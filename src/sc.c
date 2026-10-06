/* seccomp-bpf (design.md section 5.2): a deny-list filter. */
#include "lk.h"
#include <errno.h>
#include <string.h>

struct lk_sc_entry {
    const char *name;
    int nr;
};

#ifdef __linux__
#include <stdlib.h>
#include <unistd.h>
#include <sys/prctl.h>
#include "compat/seccomp_compat.h"
#include "sc_table.h"
#define LK_SC_N (sizeof lk_sc_table / sizeof lk_sc_table[0] - 1)  /* minus the sentinel */
#else
static const struct lk_sc_entry lk_sc_table[] = { { NULL, -1 } };
#define LK_SC_N 0
#endif

size_t lk_sc_count(void)
{
    return LK_SC_N;
}

const char *lk_sc_name_at(size_t i, int *nr)
{
    if (i >= LK_SC_N)
        return NULL;
    *nr = lk_sc_table[i].nr;
    return lk_sc_table[i].name;
}

int lk_sc_lookup(const char *name)
{
    for (size_t i = 0; i < LK_SC_N; i++)
        if (strcmp(lk_sc_table[i].name, name) == 0)
            return lk_sc_table[i].nr >= 0 ? lk_sc_table[i].nr : -ENOSYS;
    return -ENOENT;
}

#ifdef __linux__

int lk_sc_status(void)
{
    int r = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    return r < 0 ? -errno : r;
}

#ifdef LK_AUDIT_ARCH
static struct lk_sock_filter stmt(uint16_t code, uint32_t k)
{
    struct lk_sock_filter f = { code, 0, 0, k };
    return f;
}

static struct lk_sock_filter jump(uint16_t code, uint32_t k, uint8_t jt, uint8_t jf)
{
    struct lk_sock_filter f = { code, jt, jf, k };
    return f;
}

static int rule_ret(const struct lk_sc_rule *r, uint32_t *ret)
{
    switch (r->action) {
    case LK_SC_ERRNO:        *ret = LK_SECCOMP_RET_ERRNO | ((uint32_t) r->errnum & LK_SECCOMP_RET_DATA); return 0;
    case LK_SC_KILL_PROCESS: *ret = LK_SECCOMP_RET_KILL_PROCESS; return 0;
    case LK_SC_LOG:          *ret = LK_SECCOMP_RET_LOG; return 0;
    case LK_SC_TRAP:         *ret = LK_SECCOMP_RET_TRAP; return 0;
    }
    return -EINVAL;
}
#endif

int lk_sc_install(const struct lk_sc_rule *rules, size_t n, int deny_clone_ns, int *tsync)
{
    *tsync = 0;
#ifndef LK_AUDIT_ARCH
    (void) rules; (void) n; (void) deny_clone_ns;
    return -ENOTSUP;
#else
    size_t max = 6 + 5 + 2 * n + 1;
    if (max > 4096)
        return -E2BIG;
    for (size_t i = 0; i < n; i++) {
        uint32_t ret;
        if (rule_ret(&rules[i], &ret) != 0)
            return -EINVAL;
    }
    struct lk_sock_filter *f = malloc(max * sizeof *f);
    if (!f)
        return -ENOMEM;
    size_t k = 0;
    /* Wrong architecture (e.g. i386 calls on x86_64): numbers mean other
     * calls there, so nothing is allowed. */
    f[k++] = stmt(LK_BPF_LD | LK_BPF_W | LK_BPF_ABS, LK_SECCOMP_DATA_ARCH);
    f[k++] = jump(LK_BPF_JMP | LK_BPF_JEQ | LK_BPF_K, LK_AUDIT_ARCH, 1, 0);
    f[k++] = stmt(LK_BPF_RET | LK_BPF_K, LK_SECCOMP_RET_KILL_PROCESS);
    f[k++] = stmt(LK_BPF_LD | LK_BPF_W | LK_BPF_ABS, LK_SECCOMP_DATA_NR);
#ifdef LK_HAVE_X32_GUARD
    /* x32 calls share the arch value but set this bit: refuse them all. */
    f[k++] = jump(LK_BPF_JMP | LK_BPF_JGE | LK_BPF_K, LK_X32_SYSCALL_BIT, 0, 1);
    f[k++] = stmt(LK_BPF_RET | LK_BPF_K, LK_SECCOMP_RET_KILL_PROCESS);
#endif
#ifdef SYS_clone
    if (deny_clone_ns) {
        /* clone() creating a namespace: the door unshare() would open. */
        f[k++] = jump(LK_BPF_JMP | LK_BPF_JEQ | LK_BPF_K, (uint32_t) SYS_clone, 0, 3);
        f[k++] = stmt(LK_BPF_LD | LK_BPF_W | LK_BPF_ABS, LK_CLONE_FLAGS_OFF);
        f[k++] = jump(LK_BPF_JMP | LK_BPF_JSET | LK_BPF_K, LK_CLONE_NEW_MASK, 0, 1);
        f[k++] = stmt(LK_BPF_RET | LK_BPF_K, LK_SECCOMP_RET_ERRNO | EPERM);
        f[k++] = stmt(LK_BPF_LD | LK_BPF_W | LK_BPF_ABS, LK_SECCOMP_DATA_NR);
    }
#else
    (void) deny_clone_ns;
#endif
    for (size_t i = 0; i < n; i++) {
        uint32_t ret;
        rule_ret(&rules[i], &ret);
        f[k++] = jump(LK_BPF_JMP | LK_BPF_JEQ | LK_BPF_K, (uint32_t) rules[i].nr, 0, 1);
        f[k++] = stmt(LK_BPF_RET | LK_BPF_K, ret);
    }
    f[k++] = stmt(LK_BPF_RET | LK_BPF_K, LK_SECCOMP_RET_ALLOW);

    struct lk_sock_fprog prog;
    prog.len = (unsigned short) k;
    prog.filter = f;

    int rc = 0;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        rc = -errno;
        goto out;
    }
#ifdef LK_NR_SECCOMP
    /* TSYNC: every thread gets the filter, which matters for confine(). */
    long r = syscall(LK_NR_SECCOMP, LK_SECCOMP_SET_MODE_FILTER, LK_SECCOMP_FILTER_FLAG_TSYNC, &prog);
    if (r == 0) {
        *tsync = 1;
        goto out;
    }
    if (r < 0 && errno != EINVAL && errno != ENOSYS) {
        rc = -errno;
        goto out;
    }
    /* r > 0: a thread could not be synchronised; EINVAL: no TSYNC flag;
     * ENOSYS: no seccomp() call. Install for this thread only. */
    if (r < 0 && errno == EINVAL) {
        r = syscall(LK_NR_SECCOMP, LK_SECCOMP_SET_MODE_FILTER, 0U, &prog);
        if (r == 0)
            goto out;
        if (errno != ENOSYS) {
            rc = -errno;
            goto out;
        }
    }
#endif
    if (prctl(PR_SET_SECCOMP, LK_SECCOMP_MODE_FILTER, &prog, 0, 0) != 0)
        rc = -errno;
out:
    free(f);
    return rc;
#endif
}

int lk_sc_deny(const int *nrs, size_t n, int action, int errnum, int *tsync)
{
    struct lk_sc_rule *rules = malloc((n ? n : 1) * sizeof *rules);
    if (!rules)
        return -ENOMEM;
    for (size_t i = 0; i < n; i++) {
        rules[i].nr = nrs[i];
        rules[i].action = action;
        rules[i].errnum = errnum;
    }
    int rc = lk_sc_install(rules, n, 0, tsync);
    free(rules);
    return rc;
}

#else /* not Linux */

int lk_sc_status(void)
{
    return 0;
}

int lk_sc_install(const struct lk_sc_rule *rules, size_t n, int deny_clone_ns, int *tsync)
{
    (void) rules; (void) n; (void) deny_clone_ns;
    *tsync = 0;
    return -ENOSYS;
}

int lk_sc_deny(const int *nrs, size_t n, int action, int errnum, int *tsync)
{
    (void) nrs; (void) n; (void) action; (void) errnum;
    *tsync = 0;
    return -ENOSYS;
}

#endif
