/* SPDX-License-Identifier: GPL-2.0 */
/*
 * xloop_file_fmt_qcow_cluster.h
 *
 * Ported QCOW2 implementation of the QEMU project (GPL-2.0):
 * Cluster calculation and lookup for the QCOW2 format.
 *
 * The copyright (C) 2004-2006 of the original code is owned by Fabrice Bellard.
 *
 * Copyright (C) 2019 Manuel Bentele <development@manuel-bentele.de>
 */

#ifndef _LINUX_XLOOP_FILE_FMT_QCOW_CLUSTER_H
#define _LINUX_XLOOP_FILE_FMT_QCOW_CLUSTER_H

#include "loop_file_fmt.h"

extern int xloop_file_fmt_qcow_cluster_get_offset(struct xloop_file_fmt *xlo_fmt,
						 u64 offset,
						 unsigned int *bytes,
						 u64 *cluster_offset);

#endif
