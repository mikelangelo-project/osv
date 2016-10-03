/*
 * Copyright (c) 2004 Mellanox Technologies Ltd.  All rights reserved.
 * Copyright (c) 2004 Infinicon Corporation.  All rights reserved.
 * Copyright (c) 2004 Intel Corporation.  All rights reserved.
 * Copyright (c) 2004 Topspin Corporation.  All rights reserved.
 * Copyright (c) 2004 Voltaire Corporation.  All rights reserved.
 * Copyright (c) 2005 Sun Microsystems, Inc. All rights reserved.
 * Copyright (c) 2005, 2006, 2007 Cisco Systems.  All rights reserved.
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

#ifndef _LINUX_PORTING_H
#define _LINUX_PORTING_H

#include <osv/prex.h>

#define	GFP_KERNEL	M_WAITOK

#define BUG_ON(a)
#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))

// ofed/include/asm/biteorder.h
#if BYTE_ORDER == LITTLE_ENDIAN
#define __LITTLE_ENDIAN
#else
#define __BIG_ENDIAN
#endif

#define cpu_to_le64     htole64
#define le64_to_cpu     le64toh
#define cpu_to_le32     htole32
#define le32_to_cpu     le32toh
#define cpu_to_le16     htole16
#define le16_to_cpu     le16toh
#define cpu_to_be64     htobe64
#define be64_to_cpu     be64toh
#define cpu_to_be32     htobe32
#define be32_to_cpu     be32toh
#define cpu_to_be16     htobe16
#define be16_to_cpu     be16toh


// ofed/include/linux/kernel.h
#define container_of(ptr, type, member)                         \
({                                                              \
        __typeof(((type *)0)->member) *_p = (ptr);              \
        (type *)((char *)_p - offsetof(type, member));          \
})

#define min(x, y)     ((x) < (y) ? (x) : (y))


// ofed/include/linux/slab.h
#define	kmalloc(size, flags)        malloc(size)
#define	kzalloc(size, flags)        kmalloc((size), (flags) | M_ZERO)
#define kfree(ptr)                  free(ptr)
#define free_page(ptr)              free(ptr)

#define __be16_to_cpu   be16toh


// ofed/include/linux/page.h
#define page    vm_page

#endif /*_LINUX_PORTING_H*/
