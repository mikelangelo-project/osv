/*
 * Copyright (c) 2007 Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2007, 2008 Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef MLX4_IB_USER_H
#define MLX4_IB_USER_H

#include <linux/types.h>

/*
 * Increment this value if any changes that break userspace ABI
 * compatibility are made.
 */

#define MLX4_IB_UVERBS_NO_DEV_CAPS_ABI_VERSION	3
#define MLX4_IB_UVERBS_ABI_VERSION		4

/*
 * Make sure that all structs defined in this file remain laid out so
 * that they pack the same way on 32-bit and 64-bit architectures (to
 * avoid incompatibility between 32-bit userspace and 64-bit kernels).
 * In particular do not use pointer types -- pass pointers in __u64
 * instead.
 */

struct mlx4_ib_alloc_ucontext_resp_v3 {
	uint32_t	qp_tab_size;
	uint16_t	bf_reg_size;
	uint16_t	bf_regs_per_page;
};

struct mlx4_ib_alloc_ucontext_resp {
	uint32_t	dev_caps;
	uint32_t	qp_tab_size;
	uint16_t	bf_reg_size;
	uint16_t	bf_regs_per_page;
	uint32_t	cqe_size;
};

struct mlx4_ib_alloc_pd_resp {
	uint32_t	pdn;
	uint32_t	reserved;
};

struct mlx4_ib_create_cq {
	uint64_t	buf_addr;
	uint64_t	db_addr;
};

struct mlx4_ib_create_cq_resp {
	uint32_t	cqn;
	uint32_t	reserved;
};

struct mlx4_ib_resize_cq {
	uint64_t	buf_addr;
};

struct mlx4_ib_create_srq {
	uint64_t	buf_addr;
	uint64_t	db_addr;
};

struct mlx4_ib_create_srq_resp {
	uint32_t	srqn;
	uint32_t	reserved;
};

struct mlx4_ib_create_qp {
	uint64_t	buf_addr;
	uint64_t	db_addr;
	uint8_t	log_sq_bb_count;
	uint8_t	log_sq_stride;
	uint8_t	sq_no_prefetch;
	uint8_t	reserved[5];
};


// section for defs ported from qp.h
struct mlx4_wqe_data_seg {
        __be32                  byte_count;
        __be32                  lkey;
        __be64                  addr;
};


#endif /* MLX4_IB_USER_H */
