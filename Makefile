# SPDX-License-Identifier: GPL-2.0

loop-y						             += loop_main.o loop_file_fmt.o
obj-$(CONFIG_BLK_DEV_LOOP)	             += loop.o

obj-$(CONFIG_BLK_DEV_CRYPTOLOOP)         += cryptoloop.o

obj-$(CONFIG_BLK_DEV_LOOP_FILE_FMT_RAW)  += loop_file_fmt_raw.o

loop_file_fmt_qcow-y                     += loop_file_fmt_qcow_main.o loop_file_fmt_qcow_cluster.o loop_file_fmt_qcow_cache.o
obj-$(CONFIG_BLK_DEV_LOOP_FILE_FMT_QCOW) += loop_file_fmt_qcow.o
