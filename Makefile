# Makefile — addrchain build orchestration
#
# Targets:
#   make module    — Build kernel module (requires kernel headers)
#   make userspace — Build daemon + CLI (userspace)
#   make test      — Build and run unit tests
#   make deb       — Build Debian package (requires dpkg-deb)
#   make clean     — Clean all build artifacts

VERSION := $(shell cat VERSION 2>/dev/null || echo 0.0.0)

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

CC       = gcc
CFLAGS   = -Wall -Wextra -Werror -std=c11 -O2 -DAC_VERSION_STR=\"$(VERSION)\"
INCLUDES = -I common

# OS detection for library flags
ifeq ($(OS),Windows_NT)
    LIBS     = -ladvapi32 -lws2_32
    LIBS_CLI = -ladvapi32
    EXE      = .exe
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Darwin)
        LIBS     =
        LIBS_CLI =
    else
        LIBS     = -lpthread
        LIBS_CLI = -lpthread
    endif
    EXE =
endif

COMMON_SRCS = common/ac_chain.c common/ac_claims.c common/ac_crypto.c \
              common/ac_subnet.c common/ac_partition.c common/ac_vpn.c \
              common/ac_discover.c common/ac_userspace_platform.c

# ---- Kernel module ----
.PHONY: module
module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# ---- Userspace binaries ----
.PHONY: userspace
userspace: daemon/addrd$(EXE) cli/addrctl$(EXE)

daemon/addrd$(EXE): daemon/addrd.c daemon/addrd_sync.c daemon/addrd_vpn.c $(COMMON_SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ daemon/addrd.c daemon/addrd_sync.c daemon/addrd_vpn.c $(COMMON_SRCS) $(LIBS)

cli/addrctl$(EXE): cli/addrctl.c $(COMMON_SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(COMMON_SRCS) $(LIBS_CLI)

# ---- Userspace tests ----
TESTS = ac_chain_test ac_claims_test ac_subnet_test ac_partition_test \
        ac_discover_test ac_vpn_test

.PHONY: test
test: $(addprefix tests/, $(addsuffix $(EXE), $(TESTS)))
	@echo "=== Running all tests ==="
	@FAIL=0; for t in $(addprefix tests/, $(addsuffix $(EXE), $(TESTS))); do \
		echo "--- $$t ---"; \
		$$t 2>&1 | grep "Results" || FAIL=1; \
	done; exit $$FAIL

tests/%$(EXE): tests/%.c $(COMMON_SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LIBS_CLI)

# ---- Debian package ----
.PHONY: deb
deb: userspace
	@command -v dpkg-deb >/dev/null 2>&1 || { echo "ERROR: dpkg-deb not found (install dpkg-dev)"; exit 1; }
	@echo "Building .deb package v$(VERSION)..."
	mkdir -p dist/addrchain_$(VERSION)/DEBIAN
	mkdir -p dist/addrchain_$(VERSION)/usr/sbin
	mkdir -p dist/addrchain_$(VERSION)/usr/bin
	mkdir -p dist/addrchain_$(VERSION)/etc/addrchain
	mkdir -p dist/addrchain_$(VERSION)/usr/lib/systemd/system
	mkdir -p dist/addrchain_$(VERSION)/usr/src/addrchain-$(VERSION)
	cp daemon/addrd dist/addrchain_$(VERSION)/usr/sbin/
	cp cli/addrctl dist/addrchain_$(VERSION)/usr/bin/
	cp packaging/debian/addrchain.service dist/addrchain_$(VERSION)/usr/lib/systemd/system/
	sed "s/@VERSION@/$(VERSION)/g" packaging/debian/control > dist/addrchain_$(VERSION)/DEBIAN/control
	cp packaging/debian/postinst dist/addrchain_$(VERSION)/DEBIAN/
	cp packaging/debian/prerm dist/addrchain_$(VERSION)/DEBIAN/
	cp packaging/debian/postrm dist/addrchain_$(VERSION)/DEBIAN/
	cp packaging/debian/conffiles dist/addrchain_$(VERSION)/DEBIAN/
	chmod 755 dist/addrchain_$(VERSION)/DEBIAN/postinst
	chmod 755 dist/addrchain_$(VERSION)/DEBIAN/prerm
	chmod 755 dist/addrchain_$(VERSION)/DEBIAN/postrm
	# Copy kernel module source for DKMS
	cp -r common/ dist/addrchain_$(VERSION)/usr/src/addrchain-$(VERSION)/
	cp -r linux/ dist/addrchain_$(VERSION)/usr/src/addrchain-$(VERSION)/
	cp Kbuild dist/addrchain_$(VERSION)/usr/src/addrchain-$(VERSION)/
	sed "s/@VERSION@/$(VERSION)/g" packaging/debian/dkms.conf > dist/addrchain_$(VERSION)/usr/src/addrchain-$(VERSION)/dkms.conf
	dpkg-deb --build dist/addrchain_$(VERSION) dist/addrchain_$(VERSION)_amd64.deb
	@echo "Built: dist/addrchain_$(VERSION)_amd64.deb"

# ---- Clean ----
.PHONY: clean
clean:
	-$(MAKE) -C $(KDIR) M=$(PWD) clean 2>/dev/null || true
	rm -f tests/*$(EXE) daemon/addrd$(EXE) cli/addrctl$(EXE)
	rm -f common/*.o
	rm -rf dist/

.PHONY: all
all: test userspace
