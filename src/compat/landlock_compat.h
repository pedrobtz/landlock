/* Landlock user-space API, defined here rather than taken from the build
 * host's <linux/landlock.h> (design.md section 10).
 *
 * Why not include the system header and fill the gaps with #ifndef: a struct
 * cannot be guarded that way, and Ubuntu 24.04's header declares
 * struct landlock_ruleset_attr without the `scoped` field that ABI 6 added
 * while the kernels it runs report ABI 7. So every name here carries an
 * lk_ / LK_ prefix and the system header is never included.
 *
 * Values are from include/uapi/linux/landlock.h, GPL-2.0 WITH
 * Linux-syscall-note (user-space use permitted; see inst/COPYRIGHTS).
 */
#ifndef LK_LANDLOCK_COMPAT_H
#define LK_LANDLOCK_COMPAT_H

#ifdef __linux__
#include <stdint.h>
#include <sys/syscall.h>

/* Syscall numbers. Every architecture shares the unified numbering for
 * calls added since 5.1, so these are the same everywhere we build. */
#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif
#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif
#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif

struct lk_landlock_ruleset_attr {
    uint64_t handled_access_fs;   /* ABI 1 */
    uint64_t handled_access_net;  /* ABI 4 */
    uint64_t scoped;              /* ABI 6 */
};

struct lk_landlock_path_beneath_attr {
    uint64_t allowed_access;
    int32_t parent_fd;
} __attribute__((packed));

struct lk_landlock_net_port_attr {
    uint64_t allowed_access;
    uint64_t port;
};

#define LK_LANDLOCK_CREATE_RULESET_VERSION  (1U << 0)

#define LK_LANDLOCK_RULE_PATH_BENEATH  1
#define LK_LANDLOCK_RULE_NET_PORT      2

/* Filesystem rights. */
#define LK_FS_EXECUTE      (1ULL << 0)
#define LK_FS_WRITE_FILE   (1ULL << 1)
#define LK_FS_READ_FILE    (1ULL << 2)
#define LK_FS_READ_DIR     (1ULL << 3)
#define LK_FS_REMOVE_DIR   (1ULL << 4)
#define LK_FS_REMOVE_FILE  (1ULL << 5)
#define LK_FS_MAKE_CHAR    (1ULL << 6)
#define LK_FS_MAKE_DIR     (1ULL << 7)
#define LK_FS_MAKE_REG     (1ULL << 8)
#define LK_FS_MAKE_SOCK    (1ULL << 9)
#define LK_FS_MAKE_FIFO    (1ULL << 10)
#define LK_FS_MAKE_BLOCK   (1ULL << 11)
#define LK_FS_MAKE_SYM     (1ULL << 12)
#define LK_FS_REFER        (1ULL << 13)  /* ABI 2 */
#define LK_FS_TRUNCATE     (1ULL << 14)  /* ABI 3 */
#define LK_FS_IOCTL_DEV    (1ULL << 15)  /* ABI 5 */

/* Rights the kernel accepts on a rule whose path is not a directory. */
#define LK_FS_ACCESS_FILE  (LK_FS_EXECUTE | LK_FS_WRITE_FILE | LK_FS_READ_FILE | \
                            LK_FS_TRUNCATE | LK_FS_IOCTL_DEV)

/* Network rights, ABI 4. */
#define LK_NET_BIND_TCP     (1ULL << 0)
#define LK_NET_CONNECT_TCP  (1ULL << 1)

/* Scopes, ABI 6. */
#define LK_SCOPE_ABSTRACT_UNIX_SOCKET  (1ULL << 0)
#define LK_SCOPE_SIGNAL                (1ULL << 1)

/* landlock_restrict_self() flags, ABI 7. */
#define LK_RESTRICT_SELF_LOG_SAME_EXEC_OFF   (1U << 0)
#define LK_RESTRICT_SELF_LOG_NEW_EXEC_ON     (1U << 1)
#define LK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF  (1U << 2)

#endif /* __linux__ */
#endif /* LK_LANDLOCK_COMPAT_H */
