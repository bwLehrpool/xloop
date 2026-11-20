/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "xloop_test.h"

int main(void)
{
	char device_path[PATH_MAX];
	int device_fd = -1;
	int backing_fd = -1;
	int device_number;
	int attached = 0;
	if (test_begin() != 0)
		return test_finish();
	device_number = find_free_xloopdev(device_path, sizeof(device_path));
	if (device_number < 0) {
		tst_res(TCONF, "no free xloop device is available");
		return test_finish();
	}
	if (fill_file("test.img", 10U * 1024U, 0U) != 0) {
		tst_res(TBROK, "cannot create backing file: %s", strerror(errno));
		goto cleanup;
	}
	device_fd = attach_device(device_path, "test.img", 0U);
	if (device_fd < 0) {
		tst_res(TBROK, "cannot attach writable xloop device: %s", strerror(errno));
		goto cleanup;
	}
	attached = 1;
	backing_fd = open("test.img", O_RDWR | O_CLOEXEC);
	if (backing_fd < 0) {
		tst_res(TBROK, "cannot open backing file: %s", strerror(errno));
		goto cleanup;
	}
	if (ioctl(device_fd, XLOOP_CHANGE_FD, backing_fd) != 0 && errno == EINVAL)
		tst_res(TPASS, "XLOOP_CHANGE_FD rejects a writable xloop device with EINVAL");
	else
		tst_res(TFAIL, "XLOOP_CHANGE_FD did not reject a writable xloop device");
cleanup:
	if (attached != 0)
		(void)detach_by_fd(device_path, device_fd);
	if (backing_fd >= 0)
		(void)close(backing_fd);
	if (device_fd >= 0)
		(void)close(device_fd);
	return test_finish();
}
