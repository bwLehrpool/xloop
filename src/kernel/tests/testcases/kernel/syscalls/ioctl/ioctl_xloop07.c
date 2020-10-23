// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2020 FUJITSU LIMITED. All rights reserved.
 * Author: Yang Xu <xuyang2018.jy@cn.jujitsu.com>
 *
 * This is a basic ioctl test about xloopdevice XLOOP_SET_STATUS64
 * and XLOOP_GET_STATUS64.
 * Test its xlo_sizelimit field. If xlo_sizelimit is 0,it means max
 * available. If sizelimit is less than xloop_size, xloopsize will
 * be truncated.
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include "lapi/xloop.h"
#include "tst_test.h"

static char dev_path[1024], sys_xloop_sizepath[1024], sys_xloop_sizelimitpath[1024];
static int dev_num, dev_fd, file_fd, attach_flag;

static struct tcase {
	unsigned int set_sizelimit;
	unsigned int exp_xloopsize;
	char *message;
} tcases[] = {
	{1024 * 4096, 2048, "When sizelimit is greater than xloopsize "},
	{1024 * 512, 1024, "When sizelimit is less than xloopsize"},
};

static void verify_ioctl_xloop(unsigned int n)
{
	struct tcase *tc = &tcases[n];
	struct xloop_info64 xloopinfo, xloopinfoget;

	tst_res(TINFO, "%s", tc->message);
	memset(&xloopinfo, 0, sizeof(xloopinfo));
	memset(&xloopinfoget, 0, sizeof(xloopinfoget));

	xloopinfo.xlo_sizelimit = tc->set_sizelimit;
	TST_RETRY_FUNC(ioctl(dev_fd, XLOOP_SET_STATUS64, &xloopinfo), TST_RETVAL_EQ0);

	TST_ASSERT_INT(sys_xloop_sizepath, tc->exp_xloopsize);
	TST_ASSERT_INT(sys_xloop_sizelimitpath, tc->set_sizelimit);
	SAFE_IOCTL(dev_fd, XLOOP_GET_STATUS64, &xloopinfoget);
	if (xloopinfoget.xlo_sizelimit == tc->set_sizelimit)
		tst_res(TPASS, "XLOOP_GET_STATUS64 gets correct xlo_sizelimit(%d)", tc->set_sizelimit);
	else
		tst_res(TFAIL, "XLOOP_GET_STATUS64 gets wrong xlo_sizelimit(%llu), expect %d",
				xloopinfoget.xlo_sizelimit, tc->set_sizelimit);
	/*Reset*/
	xloopinfo.xlo_sizelimit = 0;
	TST_RETRY_FUNC(ioctl(dev_fd, XLOOP_SET_STATUS, &xloopinfo), TST_RETVAL_EQ0);
}

static void setup(void)
{
	dev_num = tst_find_free_xloopdev(dev_path, sizeof(dev_path));
	if (dev_num < 0)
		tst_brk(TBROK, "Failed to find free xloop device");

	tst_fill_file("test.img", 0, 1024 * 1024, 1);
	tst_attach_device(dev_path, "test.img");
	attach_flag = 1;

	sprintf(sys_xloop_sizepath, "/sys/block/xloop%d/size", dev_num);
	sprintf(sys_xloop_sizelimitpath, "/sys/block/xloop%d/xloop/sizelimit", dev_num);

	dev_fd = SAFE_OPEN(dev_path, O_RDWR);
	tst_res(TINFO, "original xloop size 2048 sectors");
}

static void cleanup(void)
{
	if (dev_fd > 0)
		SAFE_CLOSE(dev_fd);
	if (file_fd > 0)
		SAFE_CLOSE(file_fd);
	if (attach_flag)
		tst_detach_device(dev_path);
}

static struct tst_test test = {
	.setup = setup,
	.cleanup = cleanup,
	.test = verify_ioctl_xloop,
	.tcnt = ARRAY_SIZE(tcases),
	.needs_root = 1,
	.needs_tmpdir = 1,
	.needs_drivers = (const char *const []) {
		"xloop",
		"xloop_file_fmt_raw",
		NULL
	}
};
