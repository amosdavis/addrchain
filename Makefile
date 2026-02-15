# Makefile — addrchain build orchestration
#
# Targets:
#   make module    — Build kernel module (requires kernel headers)
#   make userspace — Build daemon + CLI (userspace)
#   make test      — Build and run unit tests
#   make clean     — Clean all build artifacts

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

CC       = gcc
CFLAGS   = -Wall -Wextra -Werror -std=c11 -O2
INCLUDES = -I common
LIBS     = -ladvapi32  # Windows; on Linux use -lpthread
COMMON_SRCS = common/ac_chain.c common/ac_claims.c common/ac_crypto.c \
              common/ac_subnet.c common/ac_partition.c common/ac_vpn.c \
              common/ac_discover.c common/ac_userspace_platform.c

# ---- Kernel module ----
.PHONY: module
module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# ---- Userspace tests ----
TESTS = ac_chain_test ac_claims_test ac_subnet_test ac_partition_test \
        ac_discover_test ac_vpn_test

.PHONY: test
test: $(addprefix tests/, $(addsuffix .exe, $(TESTS)))
	@echo "=== Running all tests ==="
	@for t in $(addprefix tests/, $(addsuffix .exe, $(TESTS))); do \
		echo "--- $$t ---"; \
		./$$t 2>&1 | grep "Results"; \
	done

tests/%.exe: tests/%.c $(COMMON_SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS)

# ---- Clean ----
.PHONY: clean
clean:
	-$(MAKE) -C $(KDIR) M=$(PWD) clean 2>/dev/null || true
	rm -f tests/*.exe common/*.o

.PHONY: all
all: test
