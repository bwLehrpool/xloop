/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "xloop_test.h"

struct block_size_case {
	uint32_t value;
	const char *description;
};

static int expect_invalid_size(int device_fd, unsigned long request, uint32_t value,
	const char *description)
{
	int result = ioctl(device_fd, request, (unsigned long)value);
	if (result != 0 && errno == EINVAL) {
		tst_res(TPASS, "%s is rejected with EINVAL", description);
		return 0;
	}
	tst_res(TFAIL, "%s was not rejected with EINVAL", description);
	return -1;
}

static int expect_invalid_config(int device_fd, struct xloop_config *config,
	const char *description)
{
	if (ioctl(device_fd, XLOOP_CONFIGURE, config) == 0) {
		tst_res(TFAIL, "%s was accepted", description);
		return 1;
	}
	if (errno == EINVAL) {
		tst_res(TPASS, "%s is rejected with EINVAL", description);
		return 0;
	}
	tst_res(TFAIL, "%s failed with %s instead of EINVAL", description, strerror(errno));
	return -1;
}

int main(void)
{
	char device_path[PATH_MAX];
	int device_number;
	int device_fd = -1;
	int backing_fd = -1;
	int attached = 0;
	struct xloop_config config;
	struct block_size_case cases[3];
	long page_size;
	unsigned int index;
	int configure_supported;
	if (test_begin() != 0)
		return test_finish();
	device_number = find_free_xloopdev(device_path, sizeof(device_path));
	if (device_number < 0) {
		tst_res(TCONF, "no free xloop device is available");
		return test_finish();
	}
	(void)device_number;
	if (fill_file("test.img", 1024U * 1024U, 0U) != 0) {
		tst_res(TBROK, "cannot create backing file: %s", strerror(errno));
		goto cleanup;
	}
	device_fd = open_device(device_path);
	backing_fd = open("test.img", O_RDWR | O_CLOEXEC);
	if (device_fd < 0 || backing_fd < 0) {
		tst_res(TBROK, "cannot open test files or device: %s", strerror(errno));
		goto cleanup;
	}
	if (ioctl(device_fd, XLOOP_SET_BLOCK_SIZE, 512UL) != 0 && errno == EINVAL) {
		tst_res(TCONF, "XLOOP_SET_BLOCK_SIZE is unsupported");
		goto cleanup;
	}
	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0 || (uint64_t)page_size > UINT32_MAX) {
		tst_res(TBROK, "cannot determine a supported page size");
		goto cleanup;
	}
	cases[0].value = 256U;
	cases[0].description = "block size below 512 bytes";
	cases[1].value = (uint32_t)((uint64_t)page_size * 2U);
	cases[1].description = "block size above PAGE_SIZE";
	cases[2].value = (uint32_t)page_size - 1U;
	cases[2].description = "non-power-of-two block size";
	for (index = 0U; index < 3U; index++)
		(void)expect_invalid_size(device_fd, XLOOP_SET_BLOCK_SIZE, cases[index].value,
			cases[index].description);
	memset(&config, 0, sizeof(config));
	config.fd = (uint32_t)backing_fd;
	configure_supported = ioctl(device_fd, XLOOP_CONFIGURE, &(struct xloop_config){ .fd = UINT32_MAX }) != 0 && errno == EBADF;
	if (configure_supported == 0) {
		tst_res(TCONF, "XLOOP_CONFIGURE is unsupported");
		goto cleanup;
	}
	for (index = 0U; index < 3U; index++) {
		config.block_size = cases[index].value;
		if (expect_invalid_config(device_fd, &config, cases[index].description) > 0) {
			(void)detach_by_fd(device_path, device_fd);
			attached = 0;
		}
	}
cleanup:
	if (attached != 0 && device_fd >= 0)
		(void)detach_by_fd(device_path, device_fd);
	if (device_fd >= 0)
		(void)close(device_fd);
	if (backing_fd >= 0)
		(void)close(backing_fd);
	return test_finish();
}
