obj-m := netdriver.o
KDIR ?= /lib/modules/$(shell uname -r)/build
#CC := aaabbbccc
all: modules
install: modules_install
modules modules_install help clean:
	$(MAKE) -C $(KDIR) M=$(shell pwd) $(@)
