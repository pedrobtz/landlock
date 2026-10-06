/* Landlock (design.md section 5.1). */
#include "lk.h"
#include <errno.h>

#ifdef __linux__
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include "compat/landlock_compat.h"

/* Newest ABI this file knows. A kernel reporting more is used at this level:
 * every newer right stays unhandled, which is the conservative reading. */
#define LK_LL_ABI_MAX 7

static int ll_create_ruleset(const struct lk_landlock_ruleset_attr *attr,
                             size_t size, uint32_t flags)
{
    return (int) syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

static int ll_add_rule(int ruleset_fd, int rule_type, const void *rule_attr)
{
    return (int) syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr, 0U);
}

static int ll_restrict_self(int ruleset_fd, uint32_t flags)
{
    return (int) syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}

int lk_ll_abi(void)
{
    int r = ll_create_ruleset(NULL, 0, LK_LANDLOCK_CREATE_RULESET_VERSION);
    if (r >= 0)
        return r;
    if (errno == ENOSYS || errno == EOPNOTSUPP)
        return 0;
    return -errno;
}

int lk_ll_errata(void)
{
    int r = ll_create_ruleset(NULL, 0, LK_LANDLOCK_CREATE_RULESET_ERRATA);
    return r >= 0 ? r : -errno;
}

uint64_t lk_ll_handled_fs(int abi)
{
    uint64_t r = 0;
    if (abi >= 1)
        r |= LK_FS_EXECUTE | LK_FS_WRITE_FILE | LK_FS_READ_FILE | LK_FS_READ_DIR |
             LK_FS_REMOVE_DIR | LK_FS_REMOVE_FILE | LK_FS_MAKE_CHAR | LK_FS_MAKE_DIR |
             LK_FS_MAKE_REG | LK_FS_MAKE_SOCK | LK_FS_MAKE_FIFO | LK_FS_MAKE_BLOCK |
             LK_FS_MAKE_SYM;
    if (abi >= 2)
        r |= LK_FS_REFER;
    if (abi >= 3)
        r |= LK_FS_TRUNCATE;
    if (abi >= 5)
        r |= LK_FS_IOCTL_DEV;
    return r;
}

/* design.md section 9: fs() mode -> rights. write does not imply read. */
static uint64_t mode_rights(unsigned mode)
{
    uint64_t r = 0;
    if (mode & LK_LL_READ)
        r |= LK_FS_READ_FILE | LK_FS_READ_DIR;
    if (mode & LK_LL_WRITE)
        r |= LK_FS_WRITE_FILE | LK_FS_REMOVE_DIR | LK_FS_REMOVE_FILE |
             LK_FS_MAKE_CHAR | LK_FS_MAKE_DIR | LK_FS_MAKE_REG | LK_FS_MAKE_SOCK |
             LK_FS_MAKE_FIFO | LK_FS_MAKE_BLOCK | LK_FS_MAKE_SYM |
             LK_FS_REFER | LK_FS_TRUNCATE | LK_FS_IOCTL_DEV;
    if (mode & LK_LL_EXEC)
        r |= LK_FS_EXECUTE | LK_FS_READ_FILE;   /* the loader reads what it maps */
    return r;
}

/* struct landlock_ruleset_attr grew with the ABI; pass the size the probed
 * ABI knows so an older kernel never sees fields it would reject. */
static size_t ruleset_attr_size(int abi)
{
    if (abi >= 6)
        return 3 * sizeof(uint64_t);
    if (abi >= 4)
        return 2 * sizeof(uint64_t);
    return sizeof(uint64_t);
}

static int add_path_rule(int ruleset_fd, const struct lk_ll_path *pp, uint64_t handled_fs)
{
    int fd = open(pp->path, O_PATH | O_CLOEXEC);
    if (fd < 0)
        return -errno;
    struct stat st;
    if (fstat(fd, &st) != 0) {
        int e = errno;
        close(fd);
        return -e;
    }
    uint64_t allowed = mode_rights(pp->mode) & handled_fs;
    if (!S_ISDIR(st.st_mode))
        allowed &= LK_FS_ACCESS_FILE;  /* the kernel rejects directory rights on files */
    int rc = 0;
    if (allowed) {
        struct lk_landlock_path_beneath_attr pb;
        memset(&pb, 0, sizeof pb);
        pb.allowed_access = allowed;
        pb.parent_fd = fd;
        if (ll_add_rule(ruleset_fd, LK_LANDLOCK_RULE_PATH_BENEATH, &pb) != 0)
            rc = -errno;
    }
    close(fd);
    return rc;
}

static int add_port_rules(int ruleset_fd, const uint16_t *ports, size_t n, uint64_t right)
{
    for (size_t i = 0; i < n; i++) {
        struct lk_landlock_net_port_attr np;
        memset(&np, 0, sizeof np);
        np.allowed_access = right;
        np.port = ports[i];
        if (ll_add_rule(ruleset_fd, LK_LANDLOCK_RULE_NET_PORT, &np) != 0)
            return -errno;
    }
    return 0;
}

int lk_ll_restrict(const struct lk_ll_policy *p, struct lk_ll_report *r)
{
    memset(r, 0, sizeof *r);
    r->failed_path = -1;

    int want_scope = p->scope_signal || p->scope_abstract_unix;
    if (!p->handle_fs && !p->handle_net && !want_scope)
        return 0;  /* nothing requested */

    int abi;
    if (p->force_abi < 0) {
        abi = 0;
    } else {
        abi = lk_ll_abi();
        if (abi < 0)
            return abi;
        if (abi > LK_LL_ABI_MAX)
            abi = LK_LL_ABI_MAX;
        if (p->force_abi > 0 && p->force_abi < abi)
            abi = p->force_abi;
    }
    r->abi = abi;

    if (abi == 0)
        return p->best_effort ? 0 : -EOPNOTSUPP;
    if (!p->best_effort &&
        ((p->handle_net && abi < 4) || (want_scope && abi < 6) || (p->log && abi < 7)))
        return -EOPNOTSUPP;

    struct lk_landlock_ruleset_attr attr;
    memset(&attr, 0, sizeof attr);
    if (p->handle_fs)
        attr.handled_access_fs = lk_ll_handled_fs(abi);
    if (p->handle_net && abi >= 4)
        attr.handled_access_net = LK_NET_BIND_TCP | LK_NET_CONNECT_TCP;
    if (abi >= 6) {
        if (p->scope_signal)
            attr.scoped |= LK_SCOPE_SIGNAL;
        if (p->scope_abstract_unix)
            attr.scoped |= LK_SCOPE_ABSTRACT_UNIX_SOCKET;
    }
    if (!attr.handled_access_fs && !attr.handled_access_net && !attr.scoped)
        return 0;  /* best effort, and nothing requested is available at this ABI */

    int rfd = ll_create_ruleset(&attr, ruleset_attr_size(abi), 0);
    if (rfd < 0)
        return -errno;

    int rc = 0;
    if (attr.handled_access_fs) {
        for (size_t i = 0; i < p->npaths; i++) {
            rc = add_path_rule(rfd, &p->paths[i], attr.handled_access_fs);
            if (rc != 0) {
                r->failed_path = (long) i;
                goto out;
            }
        }
    }
    if (attr.handled_access_net) {
        rc = add_port_rules(rfd, p->bind_ports, p->nbind, LK_NET_BIND_TCP);
        if (rc == 0)
            rc = add_port_rules(rfd, p->connect_ports, p->nconnect, LK_NET_CONNECT_TCP);
        if (rc != 0)
            goto out;
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        rc = -errno;
        goto out;
    }
    uint32_t flags = abi >= 7 ? p->log : 0;
    if (ll_restrict_self(rfd, flags) != 0) {
        rc = -errno;
        goto out;
    }

    r->fs = attr.handled_access_fs != 0;
    r->net = attr.handled_access_net != 0;
    r->scope = attr.scoped != 0;
    r->log = flags != 0;

out:
    close(rfd);
    return rc;
}

#else /* not Linux: Landlock is absent */

#include <string.h>

int lk_ll_abi(void)
{
    return 0;
}

int lk_ll_errata(void)
{
    return -ENOSYS;
}

uint64_t lk_ll_handled_fs(int abi)
{
    (void) abi;
    return 0;
}

int lk_ll_restrict(const struct lk_ll_policy *p, struct lk_ll_report *r)
{
    memset(r, 0, sizeof *r);
    r->failed_path = -1;
    if (!p->handle_fs && !p->handle_net && !p->scope_signal && !p->scope_abstract_unix)
        return 0;
    return p->best_effort ? 0 : -EOPNOTSUPP;
}

#endif
