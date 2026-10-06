/* Landlock uapi constants the core needs, defined here when the build host's
 * <linux/landlock.h> is older than the kernel the package will run on
 * (design.md §10). Ubuntu 24.04's header stops at ABI 4; the package handles
 * ABI 7. Values are from the Linux uapi headers, GPL-2.0 WITH
 * Linux-syscall-note, which permits their use in user space; see
 * inst/COPYRIGHTS and LICENSE.note.
 *
 * The landlock_* syscall numbers are asm-generic and identical on every
 * architecture.
 */
#ifndef LK_LANDLOCK_COMPAT_H
#define LK_LANDLOCK_COMPAT_H

#ifdef __linux__
#include <sys/syscall.h>

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif
#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif
#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

#endif /* __linux__ */
#endif /* LK_LANDLOCK_COMPAT_H */
