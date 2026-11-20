/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "xloop_test.h"

#define OLD_SIZE 10240U
#define NEW_SIZE 5120U

int main(void)
{
	char device_path[PATH_MAX];
	char sysfs_size[PATH_MAX];
	unsigned char buffer[OLD_SIZE];
	int device_number;
	int device_fd = -1;
	int backing_fd = -1;
	int attached = 0;
	ssize_t written;
	if (test_begin() != 0)
		return test_finish();
	device_number = find_free_xloopdev(device_path, sizeof(device_path));
	if (device_number < 0) {
		tst_res(TCONF, "no free xloop device is available");
		return test_finish();
	}
	if (fill_file("test.img", OLD_SIZE, 0U) != 0) {
		tst_res(TBROK, "cannot create backing file: %s", strerror(errno));
		return test_finish();
	}
	device_fd = open_device(device_path);
	if (device_fd < 0 || attach_by_fd(device_fd, "test.img", 0U, 0U, 0U, 0U) != 0) {
		tst_res(TBROK, "cannot attach xloop device: %s", strerror(errno));
		goto cleanup;
	}
	attached = 1;
	(void)snprintf(sysfs_size, sizeof(sysfs_size), "/sys/block/xloop%d/size", device_number);
	(void)assert_int(sysfs_size, OLD_SIZE / 512U);
	backing_fd = open("test.img", O_WRONLY | O_CLOEXEC);
	if (backing_fd < 0 || ftruncate(backing_fd, NEW_SIZE) != 0) {
		tst_res(TBROK, "cannot truncate backing file: %s", strerror(errno));
		goto cleanup;
	}
	(void)close(backing_fd);
	backing_fd = -1;
	if (ioctl(device_fd, XLOOP_SET_CAPACITY) != 0) {
		tst_res(TFAIL, "XLOOP_SET_CAPACITY failed: %s", strerror(errno));
		goto cleanup;
	}
	memset(buffer, 'x', sizeof(buffer));
	if (lseek(device_fd, 0, SEEK_SET) < 0) {
		tst_res(TBROK, "cannot seek xloop device: %s", strerror(errno));
		goto cleanup;
	}
	written = write(device_fd, buffer, sizeof(buffer));
	if (written == (ssize_t)NEW_SIZE)
		tst_res(TPASS, "XLOOP_SET_CAPACITY updates the live device size to %u bytes", NEW_SIZE);
	else
		tst_res(TFAIL, "write returned %zd bytes after capacity update, expected %u", written, NEW_SIZE);
	(void)assert_int(sysfs_size, NEW_SIZE / 512U);
cleanup:
	if (attached != 0)
		(void)detach_by_fd(device_path, device_fd);
	if (device_fd >= 0)
		(void)close(device_fd);
	if (backing_fd >= 0)
		(void)close(backing_fd);
	return test_finish();
}
