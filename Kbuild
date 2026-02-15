# Kbuild — addrchain Linux kernel module build configuration
#
# Build: make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
# Install: make -C /lib/modules/$(uname -r)/build M=$(pwd) modules_install
# Clean: make -C /lib/modules/$(uname -r)/build M=$(pwd) clean

obj-m := addrchain.o

# Module composite objects: common + linux-specific
addrchain-objs := \
	linux/ac_main.o \
	linux/ac_linux_crypto.o \
	linux/ac_netlink.o \
	linux/ac_netdev.o \
	linux/ac_sysinfo.o \
	linux/ac_pool_bridge.o \
	common/ac_chain.o \
	common/ac_claims.o \
	common/ac_crypto.o \
	common/ac_subnet.o \
	common/ac_partition.o \
	common/ac_vpn.o \
	common/ac_discover.o

# Include paths
ccflags-y := -I$(src)/common -Wall -Wextra -Werror -std=gnu11

# Debug build (set AC_DEBUG=1 to enable)
ifdef AC_DEBUG
ccflags-y += -DDEBUG -g
endif
