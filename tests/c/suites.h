/* The list of suites the harness runs. Each test_*.c file adds one line here
 * and one line to TESTS in the Makefile. */
#ifndef LK_SUITES_H
#define LK_SUITES_H
#include "harness.h"

#define LK_SUITE_LIST(X) X(suite_ll) X(suite_lim) X(suite_proc)

#endif
