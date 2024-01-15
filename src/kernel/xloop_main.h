/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/version.h>

/* define RHEL_CHECK_VERSION macro to check CentOS version */
#if defined(RHEL_RELEASE_CODE) && defined(RHEL_RELEASE_VERSION)
#define RHEL_CHECK_VERSION(CONDITION) (CONDITION)
#else
#define RHEL_CHECK_VERSION(CONDITION) (0)
#endif

#if RHEL_CHECK_VERSION(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(9, 0))
#include "xloop_main_rhel_9.0.h"
#elif RHEL_CHECK_VERSION(RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8, 5))
#include "xloop_main_rhel_8.5.h"
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0)
#include "xloop_main_4.18.h"
#elif LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
#include "xloop_main_5.15.h"
#else
#include "xloop_main_6.6.h"
#endif
