# C harness for the landlock core: builds and runs without R.
#
#   make -C tests/c && tests/c/run [name-filter]
#
# CFLAGS may be overridden (CI builds with clang -std=gnu23 -pedantic);
# -Werror and the include path are always added.

CC     ?= cc
CFLAGS ?= -std=gnu11 -O1 -g -Wall -Wextra -pedantic -Wstrict-prototypes -D_GNU_SOURCE
SRC    := ../../src
CORE   := $(SRC)/ll.c $(SRC)/lim.c $(SRC)/proc.c
TESTS  := test_ll.c test_lim.c test_proc.c
HDRS   := harness.h suites.h $(SRC)/lk.h $(wildcard $(SRC)/compat/*.h)

run: run.c $(TESTS) $(CORE) $(HDRS)
	$(CC) $(CFLAGS) -Werror -I$(SRC) -I. -o $@ run.c $(TESTS) $(CORE)

clean:
	rm -f run

.PHONY: clean
