/* landlock C core: internal API shared by ll.c, sc.c, caps.c, lim.c, proc.c
 * and the R adapter rglue.c. No R headers here (design.md §3): these files
 * build and test without R.
 *
 * Conventions: return 0 on success and -errno on failure; functions that
 * return a value return >= 0 on success and -errno otherwise. No fprintf,
 * no exit, no _exit, no globals except the syscall table.
 */
#ifndef LK_H
#define LK_H

/* Landlock ABI version: > 0 the ABI, 0 unavailable (ENOSYS, or EOPNOTSUPP
 * when the LSM is disabled at boot), < 0 -errno for anything else. Always 0
 * on non-Linux. */
int lk_ll_abi(void);

#endif
