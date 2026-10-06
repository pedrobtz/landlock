/* Minimal test harness for the landlock C core. Built without R.
 *
 * Every test runs in its own forked child, so a test that restricts itself
 * (Landlock, seccomp, capabilities, rlimits) cannot affect the next one. A
 * test returns LK_T_PASS, LK_T_FAIL or LK_T_SKIP and may write a one-line
 * reason into msg.
 */
#ifndef LK_HARNESS_H
#define LK_HARNESS_H

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

enum { LK_T_PASS = 0, LK_T_FAIL = 1, LK_T_SKIP = 2 };

typedef int (*lk_test_fn)(char *msg, size_t msglen);

struct lk_test {
    const char *name;
    lk_test_fn fn;
};

#define LK_TEST(name) static int name(char *msg, size_t msglen)

#define CHECK(cond, ...)                                   \
    do {                                                   \
        if (!(cond)) {                                     \
            snprintf(msg, msglen, __VA_ARGS__);            \
            return LK_T_FAIL;                              \
        }                                                  \
    } while (0)

#define SKIP(...)                                          \
    do {                                                   \
        snprintf(msg, msglen, __VA_ARGS__);                \
        return LK_T_SKIP;                                  \
    } while (0)

#define PASS() do { (void) msg; (void) msglen; return LK_T_PASS; } while (0)

/* A scratch directory under /tmp, created per test child. */
const char *lk_t_tmpdir(void);

/* Each suite file defines one of these, terminated by { NULL, NULL }. */
#define LK_SUITE(name) const struct lk_test name[]

#endif
