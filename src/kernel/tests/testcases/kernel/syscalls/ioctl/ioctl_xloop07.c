/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "xloop_test.h"

int main(void)
{
	char device_path[PATH_MAX];
	char sysfs_size[PATH_MAX];
	char sysfs_sizelimit[PATH_MAX];
	const uint64_t image_size = 2U * 1024U * 1024U;
	const uint64_t above_image = 4U * 1024U * 1024U;
	const uint64_t limited_size = 512U * 1024U;
	int device_number;
	int device_fd = -1;
	int attached = 0;
	struct xloop_info64 status;
	if (test_begin() != 0)
		return test_finish();
	device_number = find_free_xloopdev(device_path, sizeof(device_path));
	if (device_number < 0) {
		tst_res(TCONF, "no free xloop device is available");
		return test_finish();
	}
	if (fill_file("test.img", (size_t)image_size, 0U) != 0) {
		tst_res(TBROK, "cannot create backing file: %s", strerror(errno));
		return test_finish();
	}
	device_fd = attach_device(device_path, "test.img", 0U);
	if (device_fd < 0) {
		tst_res(TBROK, "cannot attach xloop device: %s", strerror(errno));
		goto cleanup;
	}
	attached = 1;
	(void)snprintf(sysfs_size, sizeof(sysfs_size), "/sys/block/xloop%d/size", device_number);
	(void)snprintf(sysfs_sizelimit, sizeof(sysfs_sizelimit),
		"/sys/block/xloop%d/xloop/sizelimit", device_number);
	memset(&status, 0, sizeof(status));
	status.xlo_sizelimit = above_image;
	if (retry_ioctl(device_fd, XLOOP_SET_STATUS64, &status) != 0) {
		tst_res(TFAIL, "cannot set a sizelimit larger than the backing file: %s", strerror(errno));
		goto cleanup;
	}
	(void)assert_int(sysfs_size, (int64_t)(image_size / 512U));
	(void)assert_int(sysfs_sizelimit, (int64_t)above_image);
	status.xlo_sizelimit = limited_size;
	if (retry_ioctl(device_fd, XLOOP_SET_STATUS64, &status) != 0) {
		tst_res(TFAIL, "cannot set a sizelimit smaller than the backing file: %s", strerror(errno));
		goto cleanup;
	}
	(void)assert_int(sysfs_size, (int64_t)(limited_size / 512U));
	(void)assert_int(sysfs_sizelimit, (int64_t)limited_size);
	memset(&status, 0, sizeof(status));
	if (retry_ioctl(device_fd, XLOOP_GET_STATUS64, &status) != 0 ||
		status.xlo_sizelimit != limited_size)
		tst_res(TFAIL, "XLOOP_GET_STATUS64 returned the wrong sizelimit");
	else
		tst_res(TPASS, "XLOOP_GET_STATUS64 returned the configured sizelimit");
	status.xlo_sizelimit = 0U;
	if (retry_ioctl(device_fd, XLOOP_SET_STATUS64, &status) != 0)
		tst_res(TFAIL, "cannot reset sizelimit: %s", strerror(errno));
cleanup:
	if (attached != 0)
		(void)detach_by_fd(device_path, device_fd);
	if (device_fd >= 0)
		(void)close(device_fd);
	return test_finish();
}
