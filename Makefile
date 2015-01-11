#
# Makefile for perfuser module, based on LTTng Makefile
#

ifneq ($(KERNELRELEASE),)

linux_version = $(shell pwd)/include/linux/version.h
generated_linux_version = $(shell pwd)/include/generated/uapi/linux/version.h

#
# Check for stale version.h, which can be a leftover from an old Linux
# kernel tree moved to a newer kernel version, only pruned by make
# distclean.
#
ifneq ($(wildcard $(linux_version)),)
ifneq ($(wildcard $(generated_linux_version)),)
$(error Duplicate version.h files found in $(linux_version) and $(generated_linux_version). Consider running make distclean on your kernel, or removing the stale $(linux_version) file)
endif
endif

ifneq ($(CONFIG_PERF_EVENTS),)
obj-m += perfuser.o
endif # CONFIG_PERF_EVENTS

else # KERNELRELEASE
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)
	CFLAGS = $(EXTCFLAGS)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

modules_install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

%.i: %.c
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $@

endif # KERNELRELEASE
