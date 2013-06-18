cmd_/home/user/dazuko-2.3.9/dazuko_transport.o := gcc -Wp,-MD,/home/user/dazuko-2.3.9/.dazuko_transport.o.d  -nostdinc -isystem /usr/lib/i386-linux-gnu/gcc/i686-linux-gnu/4.5.2/include  -I/usr/src/linux-headers-2.6.38-8-generic/arch/x86/include -Iinclude  -include include/generated/autoconf.h -Iubuntu/include  -D__KERNEL__ -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration -Wno-format-security -fno-delete-null-pointer-checks -O2 -m32 -msoft-float -mregparm=3 -freg-struct-return -mpreferred-stack-boundary=2 -march=i686 -mtune=generic -maccumulate-outgoing-args -Wa,-mtune=generic32 -ffreestanding -fstack-protector -DCONFIG_AS_CFI=1 -DCONFIG_AS_CFI_SIGNAL_FRAME=1 -DCONFIG_AS_CFI_SECTIONS=1 -pipe -Wno-sign-compare -fno-asynchronous-unwind-tables -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -Wframe-larger-than=1024 -fno-omit-frame-pointer -fno-optimize-sibling-calls -pg -Wdeclaration-after-statement -Wno-pointer-sign -fno-strict-overflow -fconserve-stack -DCC_HAVE_ASM_GOTO -Wall -DLINUX26_SUPPORT -DNO_CAPABILITIES -DUSE_TRYTOFREEZEVOID -DLINUX_USE_FREEZER_H -DUSE_CLASS -DUSE_NDPATH -DTASKSTRUCT_USES_PARENT -DUSE_GENERATED_AUTOCONF_H -DUSE_GENERATED_UTSRELEASE_H -DON_OPEN_SUPPORT -DON_EXEC_SUPPORT -DTRUSTED_APPLICATION_SUPPORT  -DMODULE  -D"KBUILD_STR(s)=\#s" -D"KBUILD_BASENAME=KBUILD_STR(dazuko_transport)"  -D"KBUILD_MODNAME=KBUILD_STR(dazuko)" -c -o /home/user/dazuko-2.3.9/.tmp_dazuko_transport.o /home/user/dazuko-2.3.9/dazuko_transport.c

source_/home/user/dazuko-2.3.9/dazuko_transport.o := /home/user/dazuko-2.3.9/dazuko_transport.c

deps_/home/user/dazuko-2.3.9/dazuko_transport.o := \
  include/linux/stddef.h \
  include/linux/compiler.h \
    $(wildcard include/config/sparse/rcu/pointer.h) \
    $(wildcard include/config/trace/branch/profiling.h) \
    $(wildcard include/config/profile/all/branches.h) \
    $(wildcard include/config/enable/must/check.h) \
    $(wildcard include/config/enable/warn/deprecated.h) \
  include/linux/compiler-gcc.h \
    $(wildcard include/config/arch/supports/optimized/inlining.h) \
    $(wildcard include/config/optimize/inlining.h) \
  include/linux/compiler-gcc4.h \
  include/linux/types.h \
    $(wildcard include/config/uid16.h) \
    $(wildcard include/config/lbdaf.h) \
    $(wildcard include/config/phys/addr/t/64bit.h) \
    $(wildcard include/config/64bit.h) \
  /usr/src/linux-headers-2.6.38-8-generic/arch/x86/include/asm/types.h \
    $(wildcard include/config/x86/64.h) \
    $(wildcard include/config/highmem64g.h) \
  include/asm-generic/types.h \
  include/asm-generic/int-ll64.h \
  /usr/src/linux-headers-2.6.38-8-generic/arch/x86/include/asm/bitsperlong.h \
  include/asm-generic/bitsperlong.h \
  include/linux/posix_types.h \
  /usr/src/linux-headers-2.6.38-8-generic/arch/x86/include/asm/posix_types.h \
    $(wildcard include/config/x86/32.h) \
  /usr/src/linux-headers-2.6.38-8-generic/arch/x86/include/asm/posix_types_32.h \
  /home/user/dazuko-2.3.9/dazuko_transport.h \

/home/user/dazuko-2.3.9/dazuko_transport.o: $(deps_/home/user/dazuko-2.3.9/dazuko_transport.o)

$(deps_/home/user/dazuko-2.3.9/dazuko_transport.o):
