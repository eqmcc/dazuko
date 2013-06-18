EXTRA_CFLAGS += -Wall -DLINUX26_SUPPORT
EXTRA_CFLAGS += -DNO_CAPABILITIES
EXTRA_CFLAGS += -DUSE_TRYTOFREEZEVOID
EXTRA_CFLAGS += -DLINUX_USE_FREEZER_H
EXTRA_CFLAGS += -DUSE_CLASS
EXTRA_CFLAGS += -DUSE_NDPATH
EXTRA_CFLAGS += -DTASKSTRUCT_USES_PARENT
EXTRA_CFLAGS += -DUSE_GENERATED_AUTOCONF_H
EXTRA_CFLAGS += -DUSE_GENERATED_UTSRELEASE_H
EXTRA_CFLAGS += -DON_OPEN_SUPPORT
EXTRA_CFLAGS += -DON_EXEC_SUPPORT
EXTRA_CFLAGS += -DTRUSTED_APPLICATION_SUPPORT
RM ?= rm -f
obj-m += dazuko.o
dazuko-objs := dazuko_core.o dazuko_transport.o dazuko_linux26_lsm.o dazuko_linux26.o

dummy_rule:
	$(MAKE) -C /lib/modules/2.6.38-8-generic/build SUBDIRS="/home/user/dazuko-2.3.9" modules
	touch dummy_rule

install: dummy_rule
	@! find /lib/modules/2.6.38-8-generic/ -name dazuko.ko | grep dazuko.ko || { echo "!! a dazuko module is already installed !!" ; echo "!! please delete the old version before installing this one !!" ; false ; }
	mkdir -p /lib/modules/2.6.38-8-generic/extra
	cp dazuko.ko /lib/modules/2.6.38-8-generic/extra
	/sbin/depmod -ae

test: dummy_rule
	@test `id -u` -eq 0 || { echo "!! you must be root !!" ; false ; }
	/sbin/insmod ./dazuko.ko
	/sbin/rmmod dazuko
	@echo "--> test successful :)"

dazuko:
	@echo Just type \"make\", not \"make dazuko\"


dazuko-smp:
	@echo Just type \"make\", not \"make dazuko-smp\"

clean:
	$(RM) .*.cmd *.cmd *.o dazuko.ko dazuko.mod.c dummy_rule
