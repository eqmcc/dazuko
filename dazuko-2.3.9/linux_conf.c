#ifdef USE_CONFIG_H
#include <linux/config.h>
#elif defined(USE_GENERATED_AUTOCONF_H)
#include <generated/autoconf.h>
#else
#include <linux/autoconf.h>
#endif
#include <linux/version.h>
#ifdef USE_UTSRELEASE_H
#include <linux/utsrelease.h>
#elif defined(USE_GENERATED_UTSRELEASE_H)
#include <generated/utsrelease.h>
#endif
#include <stdio.h>

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) ((a)*65536+(b)*256+(c))
#endif

int main()
{
	int config_security = 0;
	int config_security_capabilities = 0;
	int config_security_capabilities_module = 0;
	int config_smp = 0;
	int config_rsbac = 0;
	int config_x86 = 0;
	int config_x86_64 = 0;
	int config_devfs_fs = 0;
	const char *linux_version = "";
	int linux_version_minor = 0;

#ifdef CONFIG_X86
	config_x86 = 1;
#endif

#ifdef CONFIG_X86_64
	config_x86_64 = 1;
#endif

#ifdef CONFIG_SECURITY
	config_security = 1;
#endif

#ifdef CONFIG_SECURITY_CAPABILITIES
	config_security_capabilities = 1;
#endif

#ifdef CONFIG_SECURITY_CAPABILITIES_MODULE
	config_security_capabilities_module = 1;
#endif

#ifdef CONFIG_SMP
	config_smp = 1;
#endif

#ifdef CONFIG_RSBAC
	config_rsbac = 1;
#endif

#ifdef CONFIG_DEVFS_FS
	config_devfs_fs = 1;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
	linux_version = "2.2";
	linux_version_minor = LINUX_VERSION_CODE - KERNEL_VERSION(2,2,0);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	linux_version = "2.4";
	linux_version_minor = LINUX_VERSION_CODE - KERNEL_VERSION(2,4,0);
#else
	linux_version = "2.6";
	linux_version_minor = LINUX_VERSION_CODE - KERNEL_VERSION(2,6,0);
#endif

	printf("CONFIG_X86=%d\n", config_x86);
	printf("CONFIG_X86_64=%d\n", config_x86_64);
	printf("CONFIG_SECURITY=%d\n", config_security);
	printf("CONFIG_SECURITY_CAPABILITIES=%d\n", config_security_capabilities);
	printf("CONFIG_SECURITY_CAPABILITIES_MODULE=%d\n", config_security_capabilities_module);
	printf("CONFIG_SMP=%d\n", config_smp);
	printf("CONFIG_RSBAC=%d\n", config_rsbac);
	printf("CONFIG_DEVFS_FS=%d\n", config_devfs_fs);
	printf("LINUX_VERSION=%s.%d\n", linux_version, linux_version_minor);
	printf("UTS_RELEASE=%s\n", UTS_RELEASE);

	return 0;
}
