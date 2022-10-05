// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "xloop_main.h"

#if RHEL_CHECK_VERSION(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8, 5))
#include "xloop_main_rhel_8.5.c"
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0)
#include "xloop_main_4.18.c"
#else
#include "xloop_main_5.15.c"
#endif
