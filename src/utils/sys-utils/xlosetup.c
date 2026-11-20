/*
 * xlosetup - setup and control xloop devices
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "uapi_xloop.h"
#include "xloop/version.h"

#ifndef XLOOP_MAJOR
#define XLOOP_MAJOR 120
#endif
#ifndef CONFIG_BLK_DEV_XLOOP_MIN_COUNT
#define CONFIG_BLK_DEV_XLOOP_MIN_COUNT 8
#endif

#define XLOOP_CONTROL "/dev/xloop-control"
#define SYS_BLOCK "/sys/block"
#define XLOOP_FLAGS_RO XLO_FLAGS_READ_ONLY
#define MAX_RETRIES 64

enum action {
	ACTION_NONE,
	ACTION_SHOW_ALL,
	ACTION_SHOW_ONE,
	ACTION_FIND,
	ACTION_ATTACH,
	ACTION_DETACH,
	ACTION_DETACH_ALL,
	ACTION_CAPACITY,
	ACTION_SET_DIO,
	ACTION_SET_BLOCKSIZE
};

enum column_id {
	COL_NAME,
	COL_AUTOCLR,
	COL_BACK_FILE,
	COL_FILE_FMT,
	COL_BACK_INO,
	COL_BACK_MAJMIN,
	COL_MAJMIN,
	COL_OFFSET,
	COL_PARTSCAN,
	COL_RO,
	COL_SIZELIMIT,
	COL_DIO,
	COL_LOGSEC,
	COL_COUNT
};

struct column_info {
	const char *name;
	const char *help;
	bool right;
	bool numeric;
	bool boolean;
};

static const struct column_info column_info[COL_COUNT] = {
	[COL_NAME] = { "NAME", "xloop device name", false, false, false },
	[COL_AUTOCLR] = { "AUTOCLEAR", "autoclear flag set", true, false, true },
	[COL_BACK_FILE] = { "BACK-FILE", "device backing file", false, false, false },
	[COL_FILE_FMT] = { "FILE-FORMAT", "backing file format", false, false, false },
	[COL_BACK_INO] = { "BACK-INO", "backing file inode number", true, true, false },
	[COL_BACK_MAJMIN] = { "BACK-MAJ:MIN", "backing file major:minor device number", false, false, false },
	[COL_MAJMIN] = { "MAJ:MIN", "xloop device major:minor number", false, false, false },
	[COL_OFFSET] = { "OFFSET", "offset from the beginning", true, true, false },
	[COL_PARTSCAN] = { "PARTSCAN", "partscan flag set", true, false, true },
	[COL_RO] = { "RO", "read-only device", true, false, true },
	[COL_SIZELIMIT] = { "SIZELIMIT", "size limit of the file in bytes", true, true, false },
	[COL_DIO] = { "DIO", "access backing file with direct-io", true, false, true },
	[COL_LOGSEC] = { "LOG-SEC", "logical sector size in bytes", true, true, false }
};

struct xloop_device {
	char name[NAME_MAX];
	char path[PATH_MAX];
	int fd;
	bool has_fd;
	char backing_file[PATH_MAX];
	uint64_t offset;
	uint64_t sizelimit;
	uint64_t backing_inode;
	uint64_t backing_dev;
	uint64_t logical_block_size;
	uint32_t file_fmt_type;
	bool autoclear;
	bool partscan;
	bool readonly;
	bool dio;
};

static enum action requested_action;
static bool use_list;
static bool no_headings;
static bool raw_output;
static bool json_output;
static bool verbose;
static bool offset_set;
static bool sizelimit_set;
static bool blocksize_set;
static bool dio_set;
static bool dio_value;
static bool readonly_set;
static bool partscan_set;
static bool show_device;
static bool no_overlap;
static uint64_t requested_offset;
static uint64_t requested_sizelimit;
static uint64_t requested_blocksize;
static uint32_t requested_format;
static bool format_set;
static const char *filter_file;
static size_t output_columns[COL_COUNT];
static size_t output_column_count;

static void usage(FILE *stream)
{
	size_t i;
	(void)fprintf(stream,
		"Usage: xlosetup [options] [<xloopdev>]\n"
		"       xlosetup [options] -f | <xloopdev> <file>\n\n"
		"Set up and control xloop devices.\n\n"
		"Commands:\n"
		" -a, --all                     list all used devices\n"
		" -d, --detach <xloopdev>...    detach one or more devices\n"
		" -D, --detach-all              detach all used devices\n"
		" -f, --find                    find first unused device\n"
		" -c, --set-capacity <device>   resize the device\n"
		" -j, --associated <file>       list devices associated with <file>\n"
		" -L, --nooverlap               avoid conflicting devices\n\n"
		"Setup options:\n"
		" -o, --offset <num>            start at offset <num> into file\n"
		"     --sizelimit <num>         limit the device to <num> bytes\n"
		" -b, --sector-size <num>       set logical sector size\n"
		" -P, --partscan                scan for partitions\n"
		" -r, --read-only               set up a read-only device\n"
		"     --direct-io[=<on|off>]    use direct I/O on the backing file\n"
		"     --show                    print device name after setup\n"
		" -t, --type <format>           set file format (RAW, QCOW, VDI, VMDK)\n"
		" -v, --verbose                 verbose mode\n\n"
		"List output options:\n"
		" -J, --json                    use JSON output\n"
		" -l, --list                    list devices\n"
		" -n, --noheadings              omit list headings\n"
		" -O, --output <cols>           select output columns\n"
		"     --output-all              output all columns\n"
		"     --raw                     use raw output\n\n"
		" -h, --help                    display this help\n"
		" -V, --version                 display version\n\n"
		"Available output columns:\n");
	for (i = 0; i < (size_t)COL_COUNT; i++)
		(void)fprintf(stream, " %12s  %s\n", column_info[i].name,
			column_info[i].help);
}

static void print_version(void)
{
	(void)printf("xlosetup from util-linux %s\n", XLOOP_VERSION);
}

static bool starts_with_xloop(const char *name)
{
	const char *p;
	if (strncmp(name, "xloop", 5) != 0)
		return false;
	p = name + 5;
	if (!isdigit((unsigned char)*p))
		return false;
	while (isdigit((unsigned char)*p))
		p++;
	return *p == '\0';
}

static bool parse_device_number(const char *input, unsigned int *number)
{
	const char *base = strrchr(input, '/');
	char *end = NULL;
	unsigned long parsed;
	const char *digits;

	base = base ? base + 1 : input;
	if (strncmp(base, "xloop", 5) == 0)
		digits = base + 5;
	else if (strncmp(input, "/dev/xloop/", 11) == 0)
		digits = input + 11;
	else
		return false;
	if (!isdigit((unsigned char)*digits))
		return false;
	errno = 0;
	parsed = strtoul(digits, &end, 10);
	if (errno != 0 || end == digits || *end != '\0' || parsed > UINT_MAX)
		return false;
	*number = (unsigned int)parsed;
	return true;
}

static int make_device_path(unsigned int number, char *path, size_t path_size)
{
	int result;
	if (access("/dev/xloop", F_OK) == 0)
		result = snprintf(path, path_size, "/dev/xloop/%u", number);
	else
		result = snprintf(path, path_size, "/dev/xloop%u", number);
	if (result < 0 || (size_t)result >= path_size) {
		errno = ENAMETOOLONG;
		return -1;
	}
	return 0;
}

static bool is_xloop_device(const char *path)
{
	struct stat st;
	char sys_path[PATH_MAX];
	char target[PATH_MAX];
	ssize_t length;
	int result;
	const char *base;

	if (stat(path, &st) == 0 && S_ISBLK(st.st_mode) && major(st.st_rdev) == XLOOP_MAJOR)
		return true;
	if (stat(path, &st) != 0 || !S_ISBLK(st.st_mode))
		return false;
	result = snprintf(sys_path, sizeof(sys_path), "/sys/dev/block/%u:%u",
		(unsigned int)major(st.st_rdev), (unsigned int)minor(st.st_rdev));
	if (result < 0 || (size_t)result >= sizeof(sys_path))
		return false;
	length = readlink(sys_path, target, sizeof(target) - 1U);
	if (length < 0)
		return false;
	target[(size_t)length] = '\0';
	base = strrchr(target, '/');
	return starts_with_xloop(base ? base + 1 : target);
}

static int device_init(struct xloop_device *device, const char *path)
{
	unsigned int number;
	const char *base;
	struct stat st;

	memset(device, 0, sizeof(*device));
	device->fd = -1;
	if (path == NULL || *path == '\0') {
		errno = EINVAL;
		return -1;
	}
	if (stat(path, &st) == 0 && S_ISBLK(st.st_mode) && major(st.st_rdev) == XLOOP_MAJOR) {
		base = strrchr(path, '/');
		base = base ? base + 1 : path;
		if (starts_with_xloop(base))
			(void)snprintf(device->name, sizeof(device->name), "%s", base);
		else {
			(void)snprintf(device->name, sizeof(device->name), "xloop%u",
				(unsigned int)minor(st.st_rdev));
		}
		(void)snprintf(device->path, sizeof(device->path), "%s", path);
		return 0;
	}
	if (!parse_device_number(path, &number)) {
		errno = ENODEV;
		return -1;
	}
	(void)snprintf(device->name, sizeof(device->name), "xloop%u", number);
	return make_device_path(number, device->path, sizeof(device->path));
}

static int sysfs_path(const struct xloop_device *device, const char *attribute,
	char *path, size_t path_size)
{
	int result;
	if (attribute != NULL && *attribute != '\0')
		result = snprintf(path, path_size, SYS_BLOCK "/%s/%s", device->name, attribute);
	else
		result = snprintf(path, path_size, SYS_BLOCK "/%s", device->name);
	if (result < 0 || (size_t)result >= path_size) {
		errno = ENAMETOOLONG;
		return -1;
	}
	return 0;
}

static int read_text_file(const char *path, char *buffer, size_t size)
{
	FILE *file;
	size_t length;
	if (size == 0U) {
		errno = EINVAL;
		return -1;
	}
	file = fopen(path, "r");
	if (file == NULL)
		return -1;
	if (fgets(buffer, (int)size, file) == NULL) {
		int saved_errno = ferror(file) ? errno : ENODATA;
		(void)fclose(file);
		errno = saved_errno;
		return -1;
	}
	length = strlen(buffer);
	while (length > 0U && (buffer[length - 1U] == '\n' || buffer[length - 1U] == '\r'))
		buffer[--length] = '\0';
	(void)fclose(file);
	return 0;
}

static int read_sysfs_string(const struct xloop_device *device, const char *attribute,
	char *buffer, size_t size)
{
	char path[PATH_MAX];
	if (sysfs_path(device, attribute, path, sizeof(path)) != 0)
		return -1;
	return read_text_file(path, buffer, size);
}

static int read_sysfs_u64(const struct xloop_device *device, const char *attribute,
	uint64_t *value)
{
	char text[128];
	char *end = NULL;
	unsigned long long parsed;
	if (read_sysfs_string(device, attribute, text, sizeof(text)) != 0)
		return -1;
	errno = 0;
	parsed = strtoull(text, &end, 10);
	if (errno != 0 || end == text || (*end != '\0' && !isspace((unsigned char)*end))) {
		errno = EINVAL;
		return -1;
	}
	*value = (uint64_t)parsed;
	return 0;
}

static void read_device_status(struct xloop_device *device)
{
	char text[PATH_MAX];
	uint64_t value;
	struct xloop_info64 info;
	struct stat st;

	if (read_sysfs_string(device, "xloop/backing_file", device->backing_file,
		sizeof(device->backing_file)) != 0)
		device->backing_file[0] = '\0';
	if (read_sysfs_u64(device, "xloop/offset", &value) == 0)
		device->offset = value;
	if (read_sysfs_u64(device, "xloop/sizelimit", &value) == 0)
		device->sizelimit = value;
	if (read_sysfs_u64(device, "xloop/autoclear", &value) == 0)
		device->autoclear = value != 0U;
	if (read_sysfs_u64(device, "xloop/partscan", &value) == 0)
		device->partscan = value != 0U;
	if (read_sysfs_u64(device, "xloop/dio", &value) == 0)
		device->dio = value != 0U;
	if (read_sysfs_u64(device, "xloop/file_fmt_type", &value) == 0)
		device->file_fmt_type = (uint32_t)value;
	if (read_sysfs_u64(device, "ro", &value) == 0)
		device->readonly = value != 0U;
	if (read_sysfs_u64(device, "queue/logical_block_size", &value) == 0)
		device->logical_block_size = value;
	if (device->fd >= 0) {
		memset(&info, 0, sizeof(info));
		if (ioctl(device->fd, XLOOP_GET_STATUS64, &info) == 0) {
			if (device->backing_file[0] == '\0') {
				(void)snprintf(device->backing_file, sizeof(device->backing_file), "%s",
					(char *)info.xlo_file_name);
			}
			device->backing_inode = info.xlo_inode;
			device->backing_dev = info.xlo_device;
			if (device->offset == 0U)
				device->offset = info.xlo_offset;
			if (device->sizelimit == 0U)
				device->sizelimit = info.xlo_sizelimit;
			if (device->file_fmt_type == 0U)
				device->file_fmt_type = info.xlo_file_fmt_type;
			device->autoclear = (info.xlo_flags & XLO_FLAGS_AUTOCLEAR) != 0U;
			device->partscan = (info.xlo_flags & XLO_FLAGS_PARTSCAN) != 0U;
			device->readonly = device->readonly ||
				((info.xlo_flags & XLO_FLAGS_READ_ONLY) != 0U);
			device->dio = device->dio || ((info.xlo_flags & XLO_FLAGS_DIRECT_IO) != 0U);
		}
	}
	if (device->backing_file[0] != '\0' && stat(device->backing_file, &st) == 0) {
		device->backing_inode = (uint64_t)st.st_ino;
		device->backing_dev = (uint64_t)st.st_dev;
	}
	if (read_sysfs_string(device, "xloop/file_fmt_type", text, sizeof(text)) == 0) {
		if (strcmp(text, "RAW") == 0)
			device->file_fmt_type = 0U;
		else if (strcmp(text, "QCOW") == 0)
			device->file_fmt_type = 1U;
		else if (strcmp(text, "VDI") == 0)
			device->file_fmt_type = 2U;
		else if (strcmp(text, "VMDK") == 0)
			device->file_fmt_type = 3U;
	}
}

static const char *format_name(uint32_t type)
{
	switch (type) {
	case 0U: return "RAW";
	case 1U: return "QCOW";
	case 2U: return "VDI";
	case 3U: return "VMDK";
	default: return "unknown";
	}
}

static int open_control(void)
{
	return open(XLOOP_CONTROL, O_RDWR | O_CLOEXEC);
}

static int request_device_add(unsigned int number)
{
	int control_fd = open_control();
	int result;
	if (control_fd < 0)
		return -1;
	result = ioctl(control_fd, XLOOP_CTL_ADD, (int)number);
	if (result != 0 && errno == EEXIST)
		result = 0;
	(void)close(control_fd);
	return result;
}

static int open_xloop(struct xloop_device *device, int flags)
{
	int fd;
	unsigned int number;
	unsigned int retry;
	fd = open(device->path, flags | O_CLOEXEC);
	if (fd >= 0)
		return fd;
	if (errno != ENOENT && errno != ENXIO)
		return -1;
	if (!parse_device_number(device->name, &number) || request_device_add(number) != 0)
		return -1;
	for (retry = 0U; retry < 20U; retry++) {
		struct timespec delay = { .tv_sec = 0, .tv_nsec = 50000000L };
		(void)nanosleep(&delay, NULL);
		fd = open(device->path, flags | O_CLOEXEC);
		if (fd >= 0)
			return fd;
		if (errno != ENOENT && errno != ENXIO)
			return -1;
	}
	errno = ENOENT;
	return -1;
}

static int find_free_device(struct xloop_device *device)
{
	int control_fd = open_control();
	int number;
	if (control_fd >= 0) {
		number = ioctl(control_fd, XLOOP_CTL_GET_FREE);
		(void)close(control_fd);
		if (number >= 0) {
			char path[PATH_MAX];
			if (make_device_path((unsigned int)number, path, sizeof(path)) == 0 &&
				device_init(device, path) == 0)
				return 0;
		}
	}
	{
		DIR *directory = opendir(SYS_BLOCK);
		struct dirent *entry;
		if (directory != NULL) {
			while ((entry = readdir(directory)) != NULL) {
				char attr[PATH_MAX];
				char backing[PATH_MAX];
				struct xloop_device candidate;
				if (!starts_with_xloop(entry->d_name) ||
					device_init(&candidate, entry->d_name) != 0)
					continue;
				if (sysfs_path(&candidate, "xloop/backing_file", attr, sizeof(attr)) != 0 ||
					read_text_file(attr, backing, sizeof(backing)) != 0 || backing[0] != '\0')
					continue;
				candidate.fd = open(candidate.path, O_RDWR | O_CLOEXEC);
				if (candidate.fd < 0)
					continue;
				(void)close(candidate.fd);
				candidate.fd = -1;
				*device = candidate;
				(void)closedir(directory);
				return 0;
			}
			(void)closedir(directory);
		}
	}
	errno = ENODEV;
	return -1;
}

static int collect_used_devices(struct xloop_device **devices, size_t *count)
{
	DIR *directory = opendir(SYS_BLOCK);
	struct dirent *entry;
	struct xloop_device *result = NULL;
	size_t used = 0U;
	size_t capacity = 0U;
	if (directory == NULL) {
		*devices = NULL;
		*count = 0U;
		return -1;
	}
	while ((entry = readdir(directory)) != NULL) {
		struct xloop_device device;
		char path[PATH_MAX];
		if (!starts_with_xloop(entry->d_name))
			continue;
		if (device_init(&device, entry->d_name) != 0)
			continue;
		if (sysfs_path(&device, "xloop/backing_file", path, sizeof(path)) != 0 ||
			read_text_file(path, device.backing_file, sizeof(device.backing_file)) != 0 ||
			device.backing_file[0] == '\0')
			continue;
		device.fd = open_xloop(&device, O_RDONLY);
		if (device.fd >= 0) {
			device.has_fd = true;
			read_device_status(&device);
		}
		if (used == capacity) {
			size_t next_capacity = capacity == 0U ? 8U : capacity * 2U;
			struct xloop_device *grown = realloc(result, next_capacity * sizeof(*result));
			if (grown == NULL) {
				if (device.fd >= 0)
					(void)close(device.fd);
				free(result);
				(void)closedir(directory);
				return -1;
			}
			result = grown;
			capacity = next_capacity;
		}
		result[used++] = device;
	}
	(void)closedir(directory);
	*devices = result;
	*count = used;
	return 0;
}

static int parse_size(const char *text, uint64_t *value)
{
	char *end = NULL;
	unsigned long long base;
	uint64_t multiplier = 1U;
	bool decimal = false;
	unsigned int power = 0U;
	const char *suffix;
	if (text == NULL || *text == '\0' || *text == '-')
		return -1;
	errno = 0;
	base = strtoull(text, &end, 10);
	if (errno != 0 || end == text)
		return -1;
	suffix = end;
	if (*suffix != '\0') {
		char unit = (char)toupper((unsigned char)*suffix);
		switch (unit) {
		case 'K': power = 1U; break;
		case 'M': power = 2U; break;
		case 'G': power = 3U; break;
		case 'T': power = 4U; break;
		case 'P': power = 5U; break;
		case 'E': power = 6U; break;
		default: return -1;
		}
		suffix++;
		if (*suffix == 'i' || *suffix == 'I') {
			suffix++;
			if (*suffix == 'b' || *suffix == 'B')
				suffix++;
		} else {
			if (*suffix == 'B') {
				decimal = true;
				suffix++;
			} else if (*suffix == 'b') {
				suffix++;
			}
		}
		if (*suffix != '\0')
			return -1;
		for (unsigned int i = 0U; i < power; i++) {
			uint64_t factor = decimal ? UINT64_C(1000) : UINT64_C(1024);
			if (multiplier > UINT64_MAX / factor)
				return -1;
			multiplier *= factor;
		}
	}
	if ((uint64_t)base > UINT64_MAX / multiplier)
		return -1;
	*value = (uint64_t)base * multiplier;
	return 0;
}

static int parse_format(const char *text, uint32_t *format)
{
	if (strcmp(text, "RAW") == 0)
		*format = 0U;
	else if (strcmp(text, "QCOW") == 0)
		*format = 1U;
	else if (strcmp(text, "VDI") == 0)
		*format = 2U;
	else if (strcmp(text, "VMDK") == 0)
		*format = 3U;
	else
		return -1;
	return 0;
}

static int add_action(enum action action)
{
	if (requested_action != ACTION_NONE && requested_action != action) {
		warnx("options select mutually exclusive actions");
		return -1;
	}
	requested_action = action;
	return 0;
}

static int column_from_name(const char *name, size_t length, size_t *column)
{
	size_t i;
	for (i = 0U; i < (size_t)COL_COUNT; i++) {
		if (strlen(column_info[i].name) == length &&
			strncasecmp(name, column_info[i].name, length) == 0) {
			*column = i;
			return 0;
		}
	}
	warnx("unknown output column: %.*s", (int)length, name);
	return -1;
}

static int parse_columns(const char *argument)
{
	const char *begin = argument;
	output_column_count = 0U;
	while (*begin != '\0') {
		const char *end = strchr(begin, ',');
		size_t column;
		size_t length = end ? (size_t)(end - begin) : strlen(begin);
		if (length == 0U || column_from_name(begin, length, &column) != 0)
			return -1;
		if (output_column_count >= (size_t)COL_COUNT) {
			errno = E2BIG;
			return -1;
		}
		output_columns[output_column_count++] = column;
		if (end == NULL)
			break;
		begin = end + 1;
	}
	use_list = true;
	return output_column_count == 0U ? -1 : 0;
}

static int get_column_value(const struct xloop_device *device, size_t column,
	char *buffer, size_t size)
{
	struct stat st;
	unsigned int number;
	dev_t backing_dev;
	if (size == 0U)
		return -1;
	buffer[0] = '\0';
	switch (column) {
	case COL_NAME:
		(void)snprintf(buffer, size, "%s", device->path);
		break;
	case COL_AUTOCLR:
		(void)snprintf(buffer, size, "%u", device->autoclear ? 1U : 0U);
		break;
	case COL_BACK_FILE:
		(void)snprintf(buffer, size, "%s", device->backing_file);
		break;
	case COL_FILE_FMT:
		(void)snprintf(buffer, size, "%s", format_name(device->file_fmt_type));
		break;
	case COL_BACK_INO:
		if (device->backing_inode != 0U)
			(void)snprintf(buffer, size, "%" PRIu64, device->backing_inode);
		break;
	case COL_BACK_MAJMIN:
		backing_dev = (dev_t)device->backing_dev;
		if (device->backing_dev != 0U)
			(void)snprintf(buffer, size, "%u:%u", (unsigned int)major(backing_dev),
				(unsigned int)minor(backing_dev));
		break;
	case COL_MAJMIN:
		if (stat(device->path, &st) == 0 && S_ISBLK(st.st_mode))
			(void)snprintf(buffer, size, "%u:%u", (unsigned int)major(st.st_rdev),
				(unsigned int)minor(st.st_rdev));
		else if (parse_device_number(device->name, &number))
			(void)snprintf(buffer, size, "%u:%u", (unsigned int)XLOOP_MAJOR, number);
		break;
	case COL_OFFSET:
		(void)snprintf(buffer, size, "%" PRIu64, device->offset);
		break;
	case COL_PARTSCAN:
		(void)snprintf(buffer, size, "%u", device->partscan ? 1U : 0U);
		break;
	case COL_RO:
		(void)snprintf(buffer, size, "%u", device->readonly ? 1U : 0U);
		break;
	case COL_SIZELIMIT:
		(void)snprintf(buffer, size, "%" PRIu64, device->sizelimit);
		break;
	case COL_DIO:
		(void)snprintf(buffer, size, "%u", device->dio ? 1U : 0U);
		break;
	case COL_LOGSEC:
		if (device->logical_block_size != 0U)
			(void)snprintf(buffer, size, "%" PRIu64, device->logical_block_size);
		break;
	default:
		return -1;
	}
	return 0;
}

static bool device_matches_file(const struct xloop_device *device, const char *file)
{
	char canonical[PATH_MAX];
	char backing_canonical[PATH_MAX];
	const char *backing = device->backing_file;
	const char *deleted = " (deleted)";
	struct stat st1;
	struct stat st2;
	size_t backing_length = strlen(backing);
	if (strcmp(backing, file) == 0)
		return true;
	if (backing_length > strlen(deleted) &&
		strcmp(backing + backing_length - strlen(deleted), deleted) == 0)
		return strncmp(backing, file, backing_length - strlen(deleted)) == 0 &&
			file[backing_length - strlen(deleted)] == '\0';
	if (realpath(file, canonical) == NULL || realpath(backing, backing_canonical) == NULL)
		return false;
	if (strcmp(canonical, backing_canonical) == 0)
		return true;
	return stat(file, &st1) == 0 && stat(backing, &st2) == 0 &&
		st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino;
}

static int show_one(const struct xloop_device *device)
{
	struct xloop_device current = *device;
	struct xloop_info64 info;
	if (current.fd < 0) {
		current.fd = open_xloop(&current, O_RDONLY);
		if (current.fd < 0)
			return -1;
		current.has_fd = true;
	}
	read_device_status(&current);
	memset(&info, 0, sizeof(info));
	if (ioctl(current.fd, XLOOP_GET_STATUS64, &info) == 0 &&
		(info.xlo_device != 0U || info.xlo_inode != 0U)) {
		(void)printf("%s: [%04" PRId64 "]:%" PRIu64 " (%s)", current.path,
			(int64_t)info.xlo_device, (uint64_t)info.xlo_inode, current.backing_file);
	} else {
		(void)printf("%s: []: (%s)", current.path, current.backing_file);
	}
	if (current.offset != 0U)
		(void)printf(", offset %" PRIu64, current.offset);
	if (current.sizelimit != 0U)
		(void)printf(", sizelimit %" PRIu64, current.sizelimit);
	(void)printf(", file-format %s\n", format_name(current.file_fmt_type));
	if (device->fd < 0)
		(void)close(current.fd);
	return 0;
}

static int print_json_string(const char *text)
{
	const unsigned char *p = (const unsigned char *)text;
	if (putchar('"') == EOF)
		return -1;
	while (*p != 0U) {
		if (*p == '"' || *p == '\\') {
			if (putchar('\\') == EOF || putchar((int)*p) == EOF)
				return -1;
		} else if (*p < 0x20U) {
			if (printf("\\u%04x", (unsigned int)*p) < 0)
				return -1;
		} else if (putchar((int)*p) == EOF) {
			return -1;
		}
		p++;
	}
	return putchar('"') == EOF ? -1 : 0;
}

static int print_raw_field(const char *text)
{
	const unsigned char *p = (const unsigned char *)text;
	while (*p != 0U) {
		if (isspace(*p)) {
			if (printf("\\x%02x", (unsigned int)*p) < 0)
				return -1;
		} else if (putchar((int)*p) == EOF) {
			return -1;
		}
		p++;
	}
	return 0;
}

static int print_table(struct xloop_device *devices, size_t device_count)
{
	char (*values)[PATH_MAX];
	size_t *widths;
	size_t row;
	size_t col;
	size_t value_count;
	values = calloc(device_count * output_column_count, sizeof(*values));
	widths = calloc(output_column_count, sizeof(*widths));
	if ((device_count != 0U && values == NULL) || widths == NULL) {
		free(values);
		free(widths);
		return -1;
	}
	for (col = 0U; col < output_column_count; col++)
		widths[col] = no_headings ? 0U : strlen(column_info[output_columns[col]].name);
	value_count = device_count * output_column_count;
	for (row = 0U; row < device_count; row++) {
		read_device_status(&devices[row]);
		for (col = 0U; col < output_column_count; col++) {
			char *value = values[row * output_column_count + col];
			(void)get_column_value(&devices[row], output_columns[col], value, PATH_MAX);
			if (strlen(value) > widths[col])
				widths[col] = strlen(value);
		}
	}
	if (json_output) {
		char lower[100];
		int i;
		(void)printf("{\"xloopdevices\":[");
		for (row = 0U; row < device_count; row++) {
			if (row != 0U)
				(void)putchar(',');
			(void)putchar('{');
			for (col = 0U; col < output_column_count; col++) {
				const struct column_info *info = &column_info[output_columns[col]];
				const char *value = values[row * output_column_count + col];
				if (col != 0U)
					(void)putchar(',');
				for (i = 0; i < sizeof(lower) - 1 && info->name[i] != '\0'; i++) {
					lower[i] = tolower(info->name[i]);
				}
				lower[i] = '\0';
				(void)print_json_string(lower);
				(void)putchar(':');
				if (info->boolean)
					(void)printf("%s", strcmp(value, "1") == 0 ? "true" : "false");
				else if (info->numeric)
					(void)printf("%s", *value == '\0' ? "null" : value);
				else
					(void)print_json_string(value);
			}
			(void)putchar('}');
		}
		(void)printf("]}\n");
		free(values);
		free(widths);
		return 0;
	}
	if (raw_output) {
		if (!no_headings) {
			for (col = 0U; col < output_column_count; col++) {
				if (col != 0U)
					(void)putchar('\t');
				(void)print_raw_field(column_info[output_columns[col]].name);
			}
			(void)putchar('\n');
		}
		for (row = 0U; row < device_count; row++) {
			for (col = 0U; col < output_column_count; col++) {
				if (col != 0U)
					(void)putchar('\t');
				(void)print_raw_field(values[row * output_column_count + col]);
			}
			(void)putchar('\n');
		}
		free(values);
		free(widths);
		return 0;
	}
	if (!no_headings) {
		for (col = 0U; col < output_column_count; col++) {
			if (col != 0U)
				(void)putchar(' ');
			if (column_info[output_columns[col]].right)
				(void)printf("%*s", (int)widths[col], column_info[output_columns[col]].name);
			else
				(void)printf("%-*s", (int)widths[col], column_info[output_columns[col]].name);
		}
		(void)putchar('\n');
	}
	for (row = 0U; row < device_count; row++) {
		for (col = 0U; col < output_column_count; col++) {
			const char *value = values[row * output_column_count + col];
			if (col != 0U)
				(void)putchar(' ');
			if (column_info[output_columns[col]].right)
				(void)printf("%*s", (int)widths[col], value);
			else
				(void)printf("%-*s", (int)widths[col], value);
		}
		(void)putchar('\n');
	}
	(void)value_count;
	free(values);
	free(widths);
	return 0;
}

static int list_devices(const char *file_filter, bool offset_filter, uint64_t offset)
{
	struct xloop_device *devices = NULL;
	struct xloop_device *selected = NULL;
	size_t count = 0U;
	size_t selected_count = 0U;
	size_t i;
	int result = 0;
	if (collect_used_devices(&devices, &count) != 0 && errno != ENOENT)
		warn("cannot enumerate xloop devices");
	if (!use_list) {
		for (i = 0U; i < count; i++) {
			if (file_filter != NULL && !device_matches_file(&devices[i], file_filter))
				continue;
			if (offset_filter && devices[i].offset != offset)
				continue;
			if (show_one(&devices[i]) != 0) {
				warn("%s", devices[i].path);
				result = -1;
			}
		}
		goto done;
	}
	selected = calloc(count == 0U ? 1U : count, sizeof(*selected));
	if (selected == NULL) {
		result = -1;
		goto done;
	}
	for (i = 0U; i < count; i++) {
		if (file_filter != NULL && !device_matches_file(&devices[i], file_filter))
			continue;
		if (offset_filter && devices[i].offset != offset)
			continue;
		selected[selected_count++] = devices[i];
	}
	result = print_table(selected, selected_count);
	done:
	for (i = 0U; i < count; i++) {
		if (devices[i].fd >= 0)
			(void)close(devices[i].fd);
	}
	free(selected);
	free(devices);
	return result;
}

static int clear_device(struct xloop_device *device)
{
	int fd = open_xloop(device, O_RDWR);
	if (fd < 0)
		fd = open_xloop(device, O_RDONLY);
	if (fd < 0)
		return -1;
	if (ioctl(fd, XLOOP_CLR_FD) != 0) {
		int saved_errno = errno;
		(void)close(fd);
		errno = saved_errno;
		return -1;
	}
	(void)close(fd);
	return 0;
}

static int detach_all(void)
{
	struct xloop_device *devices = NULL;
	size_t count = 0U;
	size_t i;
	int result = 0;
	if (collect_used_devices(&devices, &count) != 0)
		return errno == ENOENT ? 0 : -1;
	for (i = 0U; i < count; i++) {
		if (clear_device(&devices[i]) != 0) {
			warn("%s: detach failed", devices[i].path);
			result = -1;
		}
		if (devices[i].fd >= 0)
			(void)close(devices[i].fd);
	}
	free(devices);
	return result;
}

static int try_get_overlap(const char *file, uint64_t offset, uint64_t sizelimit,
	struct xloop_device *reuse)
{
	struct xloop_device *devices = NULL;
	size_t count = 0U;
	size_t i;
	struct stat file_stat;
	if (collect_used_devices(&devices, &count) != 0)
		return -1;
	for (i = 0U; i < count; i++) {
		uint64_t existing_size = devices[i].sizelimit;
		uint64_t new_size = sizelimit;
		bool same = device_matches_file(&devices[i], file);
		if (!same)
			continue;
		if (devices[i].offset == offset && existing_size == new_size) {
			*reuse = devices[i];
			for (size_t j = 0U; j < count; j++) {
				if (j != i && devices[j].fd >= 0)
					(void)close(devices[j].fd);
			}
			free(devices);
			return 2;
		}
		if (stat(file, &file_stat) == 0 && file_stat.st_size >= 0) {
			uint64_t file_size = (uint64_t)file_stat.st_size;
			uint64_t old_end = devices[i].offset + (existing_size == 0U ? file_size : existing_size);
			uint64_t new_end = offset + (new_size == 0U ? file_size : new_size);
			if (devices[i].offset < new_end && offset < old_end) {
				for (size_t j = 0U; j < count; j++) {
					if (devices[j].fd >= 0)
						(void)close(devices[j].fd);
				}
				free(devices);
				return 1;
			}
		}
	}
	for (i = 0U; i < count; i++) {
		if (devices[i].fd >= 0)
			(void)close(devices[i].fd);
	}
	free(devices);
	return 0;
}

static int reopen_backing(const char *file, bool readonly, bool direct_io)
{
	int flags = readonly ? O_RDONLY : O_RDWR;
	if (direct_io)
		flags |= O_DIRECT;
	return open(file, flags | O_CLOEXEC);
}

static int setup_device(struct xloop_device *device, const char *file)
{
	int backing_fd = -1;
	int device_fd = -1;
	bool read_only = readonly_set;
	bool retried_read_only = false;
	bool configured = false;
	unsigned int tries = 0U;
	struct stat backing_stat;
	struct xloop_config config;
	struct xloop_info64 status;
	int setup_errno = 0;
	if (stat(file, &backing_stat) == 0 && S_ISREG(backing_stat.st_mode)) {
		uint64_t file_size = (uint64_t)backing_stat.st_size;
		if (requested_offset > file_size ||
			(sizelimit_set && requested_sizelimit > file_size - requested_offset)) {
			warnx("%s: offset or size limit exceeds backing file size", file);
			errno = EINVAL;
			return -1;
		}
	}
	backing_fd = reopen_backing(file, read_only, dio_set && dio_value);
	if (backing_fd < 0 && !read_only && (errno == EACCES || errno == EROFS)) {
		read_only = true;
		retried_read_only = true;
		backing_fd = reopen_backing(file, true, dio_set && dio_value);
	}
	if (backing_fd < 0)
		return -1;
	device_fd = open_xloop(device, O_RDWR);
	if (device_fd < 0)
		goto fail;
	memset(&config, 0, sizeof(config));
	config.fd = (uint32_t)backing_fd;
	if (blocksize_set) {
		if (requested_blocksize > UINT32_MAX) {
			errno = EOVERFLOW;
			goto fail;
		}
		config.block_size = (uint32_t)requested_blocksize;
	}
	config.info.xlo_offset = requested_offset;
	config.info.xlo_sizelimit = sizelimit_set ? requested_sizelimit : 0U;
	config.info.xlo_flags = (read_only ? XLO_FLAGS_READ_ONLY : 0U) |
		(partscan_set ? XLO_FLAGS_PARTSCAN : 0U);
	config.info.xlo_file_fmt_type = format_set ? requested_format : 0U;
	for (tries = 0U; tries < MAX_RETRIES; tries++) {
		if (ioctl(device_fd, XLOOP_CONFIGURE, &config) == 0) {
			configured = true;
			setup_errno = 0;
			break;
		}
		setup_errno = errno;
		if (setup_errno == EINVAL || setup_errno == ENOTTY) {
			memset(&status, 0, sizeof(status));
			status.xlo_offset = config.info.xlo_offset;
			status.xlo_sizelimit = config.info.xlo_sizelimit;
			status.xlo_flags = config.info.xlo_flags;
			status.xlo_file_fmt_type = config.info.xlo_file_fmt_type;
			if (ioctl(device_fd, XLOOP_SET_FD, backing_fd) == 0) {
				if (ioctl(device_fd, XLOOP_SET_STATUS64, &status) == 0) {
					configured = true;
					setup_errno = 0;
					break;
				}
				setup_errno = errno;
				(void)ioctl(device_fd, XLOOP_CLR_FD);
			}
			if (setup_errno == 0)
				setup_errno = errno;
			break;
		}
		if (setup_errno == EAGAIN) {
			struct timespec delay = { .tv_sec = 0, .tv_nsec = 200000000L };
			(void)nanosleep(&delay, NULL);
			continue;
		}
		if ((setup_errno == EROFS || setup_errno == EACCES) && !read_only && !retried_read_only) {
			(void)close(backing_fd);
			read_only = true;
			retried_read_only = true;
			backing_fd = reopen_backing(file, true, dio_set && dio_value);
			if (backing_fd < 0)
				goto fail;
			config.fd = (uint32_t)backing_fd;
			config.info.xlo_flags |= XLO_FLAGS_READ_ONLY;
			continue;
		}
		break;
	}
	if (tries == MAX_RETRIES) {
		setup_errno = EAGAIN;
		goto fail;
	}
	if (!configured) {
		if (setup_errno == 0)
			setup_errno = EIO;
		goto fail;
	}
	if (dio_set && ioctl(device_fd, XLOOP_SET_DIRECT_IO,
		(unsigned long)(dio_value ? 1U : 0U)) != 0) {
		setup_errno = errno;
		(void)ioctl(device_fd, XLOOP_CLR_FD);
		goto fail;
	}
	if (blocksize_set && ioctl(device_fd, XLOOP_SET_BLOCK_SIZE,
		(unsigned long)requested_blocksize) != 0) {
		setup_errno = errno;
		(void)ioctl(device_fd, XLOOP_CLR_FD);
		goto fail;
	}
	if (ioctl(device_fd, XLOOP_SET_CAPACITY) != 0 && errno != EINVAL && errno != ENOTTY) {
		setup_errno = errno;
		(void)ioctl(device_fd, XLOOP_CLR_FD);
		goto fail;
	}
	if (verbose)
		(void)fprintf(stderr, "%s: attached %s\n", device->path, file);
	(void)close(backing_fd);
	(void)close(device_fd);
	return 0;
	fail:
	if (setup_errno != 0)
		errno = setup_errno;
	if (device_fd >= 0)
		(void)close(device_fd);
	if (backing_fd >= 0)
		(void)close(backing_fd);
	return -1;
}

static int reuse_device(struct xloop_device *device)
{
	struct xloop_info64 info;
	int fd = open_xloop(device, O_RDWR);
	if (fd < 0)
		return -1;
	memset(&info, 0, sizeof(info));
	if (ioctl(fd, XLOOP_GET_STATUS64, &info) != 0) {
		int saved_errno = errno;
		(void)close(fd);
		errno = saved_errno;
		return -1;
	}
	if ((info.xlo_flags & XLO_FLAGS_READ_ONLY) != 0U && !readonly_set) {
		(void)close(fd);
		errno = EROFS;
		return -1;
	}
	info.xlo_flags &= ~((uint32_t)XLO_FLAGS_AUTOCLEAR);
	if (ioctl(fd, XLOOP_SET_STATUS64, &info) != 0) {
		int saved_errno = errno;
		(void)close(fd);
		errno = saved_errno;
		return -1;
	}
	if (verbose)
		(void)fprintf(stderr, "%s: reusing existing device\n", device->path);
	(void)close(fd);
	return 0;
}

static int attach(const char *requested_device, const char *file)
{
	struct xloop_device device;
	bool explicit_device = requested_device != NULL;
	int overlap;
	unsigned int tries;
	if (explicit_device) {
		if (device_init(&device, requested_device) != 0) {
			warn("%s: invalid xloop device", requested_device);
			return -1;
		}
	} else if (find_free_device(&device) != 0) {
		warn("cannot find an unused xloop device");
		return -1;
	}
	if (no_overlap) {
		struct xloop_device existing;
		overlap = try_get_overlap(file, requested_offset,
			sizelimit_set ? requested_sizelimit : 0U, &existing);
		if (overlap < 0) {
			warn("failed to inspect xloop devices");
			return -1;
		}
		if (overlap == 1) {
			warnx("%s: overlapping xloop device exists", file);
			return -1;
		}
		if (overlap == 2) {
			if (explicit_device && strcmp(device.name, existing.name) != 0) {
				warnx("%s: overlapping xloop device exists", file);
				return -1;
			}
			if (reuse_device(&existing) != 0) {
				warn("%s: failed to reuse xloop device", existing.path);
				return -1;
			}
			device = existing;
			if (show_device)
				(void)printf("%s\n", device.path);
			return 0;
		}
	}
	for (tries = 0U; tries < MAX_RETRIES; tries++) {
		if (setup_device(&device, file) == 0) {
			if (show_device)
				(void)printf("%s\n", device.path);
			return 0;
		}
		if (!explicit_device && (errno == EBUSY || errno == EAGAIN)) {
			struct timespec delay = { .tv_sec = 0, .tv_nsec = 200000000L };
			(void)nanosleep(&delay, NULL);
			if (find_free_device(&device) == 0)
				continue;
		}
		warn("%s: failed to set up xloop device", file);
		return -1;
	}
	errno = EAGAIN;
	warn("%s: failed to set up xloop device", file);
	return -1;
}

static int set_device_option(const char *path, unsigned long request, unsigned long value)
{
	struct xloop_device device;
	int fd;
	if (device_init(&device, path) != 0 || !is_xloop_device(path)) {
		errno = ENODEV;
		return -1;
	}
	fd = open_xloop(&device, O_RDWR);
	if (fd < 0)
		return -1;
	if (ioctl(fd, request, value) != 0) {
		int saved_errno = errno;
		(void)close(fd);
		errno = saved_errno;
		return -1;
	}
	(void)close(fd);
	return 0;
}

static int set_capacity(const char *path)
{
	struct xloop_device device;
	int fd;
	if (device_init(&device, path) != 0 || !is_xloop_device(path)) {
		errno = ENODEV;
		return -1;
	}
	fd = open_xloop(&device, O_RDWR);
	if (fd < 0)
		return -1;
	if (ioctl(fd, XLOOP_SET_CAPACITY) != 0) {
		int saved_errno = errno;
		(void)close(fd);
		errno = saved_errno;
		return -1;
	}
	(void)close(fd);
	return 0;
}

static int detach_named(const char *path)
{
	struct xloop_device device;
	if (device_init(&device, path) != 0 || !is_xloop_device(path)) {
		errno = ENODEV;
		return -1;
	}
	return clear_device(&device);
}

static int add_default_columns(void)
{
	static const size_t defaults[] = {
		COL_NAME, COL_SIZELIMIT, COL_OFFSET, COL_AUTOCLR, COL_RO,
		COL_BACK_FILE, COL_FILE_FMT, COL_DIO, COL_LOGSEC
	};
	if (output_column_count != 0U)
		return 0;
	memcpy(output_columns, defaults, sizeof(defaults));
	output_column_count = sizeof(defaults) / sizeof(defaults[0]);
	return 0;
}

int main(int argc, char **argv)
{
	enum {
		OPT_SIZELIMIT = CHAR_MAX + 1,
		OPT_DIO,
		OPT_SHOW,
		OPT_RAW,
		OPT_OUTPUT_ALL
	};
	static const struct option options[] = {
		{ "all", no_argument, NULL, 'a' },
		{ "set-capacity", required_argument, NULL, 'c' },
		{ "detach", required_argument, NULL, 'd' },
		{ "detach-all", no_argument, NULL, 'D' },
		{ "find", no_argument, NULL, 'f' },
		{ "nooverlap", no_argument, NULL, 'L' },
		{ "help", no_argument, NULL, 'h' },
		{ "associated", required_argument, NULL, 'j' },
		{ "json", no_argument, NULL, 'J' },
		{ "list", no_argument, NULL, 'l' },
		{ "sector-size", required_argument, NULL, 'b' },
		{ "noheadings", no_argument, NULL, 'n' },
		{ "offset", required_argument, NULL, 'o' },
		{ "output", required_argument, NULL, 'O' },
		{ "output-all", no_argument, NULL, OPT_OUTPUT_ALL },
		{ "sizelimit", required_argument, NULL, OPT_SIZELIMIT },
		{ "partscan", no_argument, NULL, 'P' },
		{ "read-only", no_argument, NULL, 'r' },
		{ "direct-io", optional_argument, NULL, OPT_DIO },
		{ "raw", no_argument, NULL, OPT_RAW },
		{ "show", no_argument, NULL, OPT_SHOW },
		{ "type", required_argument, NULL, 't' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "version", no_argument, NULL, 'V' },
		{ NULL, 0, NULL, 0 }
	};
	int option;
	int result = 0;
	const char *file = NULL;
	const char *device_argument = NULL;
	bool action_explicit = false;
	bool find_option = false;
	bool detach_option = false;
	bool detach_all_option = false;
	bool all_option = false;
	bool capacity_option = false;
	bool associated_option = false;
	bool list_option = false;
	bool output_option = false;
	bool raw_option = false;
	bool json_option = false;

	while ((option = getopt_long(argc, argv, "ab:c:d:Dfhj:JlLno:O:Prt:vV", options, NULL)) != -1) {
		switch (option) {
		case 'a':
			if (add_action(ACTION_SHOW_ALL) != 0) return EXIT_FAILURE;
			all_option = true;
			break;
		case 'b':
			if (parse_size(optarg, &requested_blocksize) != 0) {
				warnx("failed to parse logical block size: %s", optarg);
				return EXIT_FAILURE;
			}
			blocksize_set = true;
			break;
		case 'c':
			if (add_action(ACTION_CAPACITY) != 0) return EXIT_FAILURE;
			capacity_option = true;
			device_argument = optarg;
			action_explicit = true;
			break;
		case 'd':
			if (add_action(ACTION_DETACH) != 0) return EXIT_FAILURE;
			detach_option = true;
			if (device_argument == NULL)
				device_argument = optarg;
			action_explicit = true;
			break;
		case 'D':
			if (add_action(ACTION_DETACH_ALL) != 0) return EXIT_FAILURE;
			detach_all_option = true;
			action_explicit = true;
			break;
		case 'f':
			if (add_action(ACTION_FIND) != 0) return EXIT_FAILURE;
			find_option = true;
			action_explicit = true;
			break;
		case 'h':
			usage(stdout);
			return EXIT_SUCCESS;
		case 'j':
			if (add_action(ACTION_SHOW_ALL) != 0) return EXIT_FAILURE;
			filter_file = optarg;
			associated_option = true;
			break;
		case 'J':
			json_output = true;
			json_option = true;
			use_list = true;
			break;
		case 'l':
			list_option = true;
			use_list = true;
			break;
		case 'L':
			no_overlap = true;
			break;
		case 'n':
			no_headings = true;
			break;
		case 'o':
			if (parse_size(optarg, &requested_offset) != 0) {
				warnx("failed to parse offset: %s", optarg);
				return EXIT_FAILURE;
			}
			offset_set = true;
			break;
		case 'O':
			if (parse_columns(optarg) != 0)
				return EXIT_FAILURE;
			output_option = true;
			break;
		case 'P':
			partscan_set = true;
			break;
		case 'r':
			readonly_set = true;
			break;
		case 't':
			if (parse_format(optarg, &requested_format) != 0) {
				warnx("failed to parse file format type: %s", optarg);
				return EXIT_FAILURE;
			}
			format_set = true;
			break;
		case 'v':
			verbose = true;
			break;
		case 'V':
			print_version();
			return EXIT_SUCCESS;
		case OPT_SIZELIMIT:
			if (parse_size(optarg, &requested_sizelimit) != 0) {
				warnx("failed to parse size: %s", optarg);
				return EXIT_FAILURE;
			}
			sizelimit_set = true;
			break;
		case OPT_DIO:
			dio_set = true;
			dio_value = true;
			if (optarg != NULL) {
				if (strcmp(optarg, "on") == 0)
					dio_value = true;
				else if (strcmp(optarg, "off") == 0)
					dio_value = false;
				else {
					warnx("invalid --direct-io argument: %s", optarg);
					return EXIT_FAILURE;
				}
			}
			break;
		case OPT_SHOW:
			show_device = true;
			break;
		case OPT_RAW:
			raw_output = true;
			raw_option = true;
			use_list = true;
			break;
		case OPT_OUTPUT_ALL:
			output_column_count = 0U;
			for (size_t i = 0U; i < (size_t)COL_COUNT; i++)
				output_columns[output_column_count++] = i;
			use_list = true;
			output_option = true;
			break;
		default:
			usage(stderr);
			return EXIT_FAILURE;
		}
	}
	if (raw_option && json_option) {
		warnx("--raw and --json are mutually exclusive");
		return EXIT_FAILURE;
	}
	if (detach_all_option && (all_option || detach_option || find_option || associated_option ||
		capacity_option || list_option || output_option)) {
		warnx("--detach-all cannot be combined with other actions");
		return EXIT_FAILURE;
	}
	if (capacity_option && (detach_option || find_option || all_option || associated_option)) {
		warnx("incompatible action options");
		return EXIT_FAILURE;
	}
	if (detach_option && (find_option || all_option || associated_option)) {
		warnx("incompatible action options");
		return EXIT_FAILURE;
	}
	if (find_option && (all_option || associated_option)) {
		warnx("incompatible action options");
		return EXIT_FAILURE;
	}
	if (argc == 1) {
		use_list = true;
		requested_action = ACTION_SHOW_ALL;
	}
	if (!action_explicit && (json_output || raw_output) && optind == argc)
		requested_action = ACTION_SHOW_ALL;
	if (requested_action == ACTION_FIND && optind < argc) {
		file = argv[optind++];
		requested_action = ACTION_ATTACH;
	}
	if (requested_action == ACTION_NONE && use_list && optind == argc)
		requested_action = ACTION_SHOW_ALL;
	if (requested_action == ACTION_NONE && optind < argc) {
		if (optind + 1 == argc) {
			device_argument = argv[optind++];
			requested_action = dio_set ? ACTION_SET_DIO :
				(blocksize_set ? ACTION_SET_BLOCKSIZE : ACTION_SHOW_ONE);
		} else {
			device_argument = argv[optind++];
			file = argv[optind++];
			requested_action = ACTION_ATTACH;
		}
	}
	if (requested_action == ACTION_FIND && optind == argc) {
		struct xloop_device free_device;
		if (find_free_device(&free_device) != 0) {
			warn("cannot find an unused xloop device");
			return EXIT_FAILURE;
		}
		(void)printf("%s\n", free_device.path);
		return EXIT_SUCCESS;
	}
	if (requested_action == ACTION_ATTACH && file == NULL) {
		warnx("no backing file specified");
		return EXIT_FAILURE;
	}
	if (requested_action == ACTION_ATTACH && (optind < argc)) {
		warnx("unexpected arguments");
		return EXIT_FAILURE;
	}
	if ((requested_action == ACTION_SHOW_ALL || requested_action == ACTION_SHOW_ONE) &&
		(sizelimit_set || readonly_set || partscan_set || format_set || show_device)) {
		warnx("setup-only options used outside device setup");
		return EXIT_FAILURE;
	}
	if (offset_set && requested_action != ACTION_ATTACH &&
		!(requested_action == ACTION_SHOW_ALL && (all_option || associated_option || use_list))) {
		warnx("--offset is not allowed in this context");
		return EXIT_FAILURE;
	}
	if (requested_action == ACTION_SHOW_ALL && use_list)
		(void)add_default_columns();
	if (requested_action == ACTION_SHOW_ONE && use_list)
		(void)add_default_columns();
	if (requested_action == ACTION_SHOW_ALL)
		result = list_devices(filter_file, offset_set, requested_offset);
	else if (requested_action == ACTION_SHOW_ONE) {
		struct xloop_device device;
		if (device_init(&device, device_argument) != 0 || !is_xloop_device(device_argument)) {
			warn("%s: failed to use device", device_argument);
			return EXIT_FAILURE;
		}
		if (use_list) {
			device.fd = open_xloop(&device, O_RDONLY);
			if (device.fd < 0) {
				warn("%s", device.path);
				return EXIT_FAILURE;
			}
			read_device_status(&device);
			result = print_table(&device, 1U);
			(void)close(device.fd);
		} else if (show_one(&device) != 0) {
			warn("%s", device.path);
			result = -1;
		}
	} else if (requested_action == ACTION_FIND) {
		struct xloop_device free_device;
		if (find_free_device(&free_device) != 0)
			result = -1;
		else
			(void)printf("%s\n", free_device.path);
	} else if (requested_action == ACTION_ATTACH) {
		result = attach(device_argument, file);
	} else if (requested_action == ACTION_DETACH) {
		if (device_argument == NULL) {
			warnx("no xloop device specified");
			return EXIT_FAILURE;
		}
		if (detach_named(device_argument) != 0) {
			warn("%s: detach failed", device_argument);
			result = -1;
		}
		while (optind < argc) {
			if (detach_named(argv[optind]) != 0) {
				warn("%s: detach failed", argv[optind]);
				result = -1;
			}
			optind++;
		}
	} else if (requested_action == ACTION_DETACH_ALL) {
		result = detach_all();
	} else if (requested_action == ACTION_CAPACITY) {
		if (set_capacity(device_argument) != 0) {
			warn("%s: set capacity failed", device_argument);
			result = -1;
		}
	} else if (requested_action == ACTION_SET_DIO) {
		if (set_device_option(device_argument, XLOOP_SET_DIRECT_IO,
			(unsigned long)(dio_value ? 1U : 0U)) != 0) {
			warn("%s: set direct io failed", device_argument);
			result = -1;
		}
	} else if (requested_action == ACTION_SET_BLOCKSIZE) {
		if (set_device_option(device_argument, XLOOP_SET_BLOCK_SIZE,
			(unsigned long)requested_blocksize) != 0) {
			warn("%s: set logical block size failed", device_argument);
			result = -1;
		}
	} else {
		usage(stderr);
		return EXIT_FAILURE;
	}
	return result == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
