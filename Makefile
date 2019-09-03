obj-m := netdriver.o
#KDIR ?= /lib/modules/$(shell uname -r)/build
KDIR ?= /home/jonathan/Softwares/openwrt/sdk/openwrt-sdk-18.06.4-x86-64_gcc-7.3.0_musl.Linux-x86_64/build_dir/target-x86_64_musl/linux-x86_64/linux-4.14.131
CC := /home/jonathan/Softwares/openwrt/sdk/openwrt-sdk-18.06.4-x86-64_gcc-7.3.0_musl.Linux-x86_64/staging_dir/toolchain-x86_64_gcc-7.3.0_musl/bin/x86_64-openwrt-linux-gcc
all: modules
install: modules_install
modules modules_install help clean:
	$(MAKE) -C $(KDIR) M=$(shell pwd) $(@)
