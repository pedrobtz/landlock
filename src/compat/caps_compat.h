/* Capability user-space API under lk_/LK_ names (design.md section 10).
 * Values are from include/uapi/linux/{capability,prctl}.h,
 * GPL-2.0 WITH Linux-syscall-note (see inst/COPYRIGHTS). */
#ifndef LK_CAPS_COMPAT_H
#define LK_CAPS_COMPAT_H

#ifdef __linux__
#include <stdint.h>
#include <sys/syscall.h>

#define LK_LINUX_CAPABILITY_VERSION_3  0x20080522U
#define LK_CAP_LAST_CAP_FALLBACK       40   /* CAP_CHECKPOINT_RESTORE, 5.9 */

struct lk_cap_header {   /* struct __user_cap_header_struct */
    uint32_t version;
    int pid;
};

struct lk_cap_data {     /* struct __user_cap_data_struct, two of them for v3 */
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};

#ifndef PR_CAPBSET_READ
#define PR_CAPBSET_READ 23
#endif
#ifndef PR_CAPBSET_DROP
#define PR_CAPBSET_DROP 24
#endif
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#endif
#ifndef PR_SET_MDWE
#define PR_SET_MDWE 65                 /* Linux 6.3 */
#endif
#ifndef PR_MDWE_REFUSE_EXEC_GAIN
#define PR_MDWE_REFUSE_EXEC_GAIN (1UL << 0)
#endif
#ifndef PR_CAP_AMBIENT_CLEAR_ALL
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

#endif /* __linux__ */
#endif /* LK_CAPS_COMPAT_H */
