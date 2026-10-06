/* Landlock (design.md §5.1). */
#include "lk.h"
#include <errno.h>

#ifdef __linux__
#include <stddef.h>
#include <unistd.h>
#include "compat/landlock_compat.h"

int lk_ll_abi(void)
{
    long r = syscall(__NR_landlock_create_ruleset, (void *) 0, (size_t) 0,
                     LANDLOCK_CREATE_RULESET_VERSION);
    if (r >= 0)
        return (int) r;
    if (errno == ENOSYS || errno == EOPNOTSUPP)
        return 0;
    return -errno;
}

#else /* not Linux: every Landlock entry point is a stub reporting "absent" */

int lk_ll_abi(void)
{
    return 0;
}

#endif
