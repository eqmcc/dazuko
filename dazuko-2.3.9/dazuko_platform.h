#if defined(DUMMYOS)
	#include "dazuko_dummyos.h"
#elif defined(LINUX26_SUPPORT)
	#include "dazuko_linux26.h"
#elif defined(LINUX)
	#include "dazuko_linux.h"
#elif defined(FREEBSD5_SUPPORT)
	#include "dazuko_freebsd5.h"
#elif defined(FREEBSD7_SUPPORT)
	#include "dazuko_freebsd5.h"
#elif defined(FREEBSD8_SUPPORT)
	#include "dazuko_freebsd5.h"
#elif defined(__FreeBSD__)
	#include "dazuko_freebsd.h"
#else
	/* fallback to Linux */
	#include <linux/config.h>
	#include <linux/version.h>

	#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
		#include "dazuko_linux.h"
	#else
		#include "dazuko_linux26.h"
	#endif
#endif
