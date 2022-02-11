#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0)
#include "xloop_main_4.18.h"
#else
#include "xloop_main_5.15.h"
#endif
