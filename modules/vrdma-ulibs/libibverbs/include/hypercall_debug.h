/*
 * Hybrid Virtualization (HyV) for Linux
 *
 * Author: Jonas Pfefferle <jpf@zurich.ibm.com>
 *
 * Copyright (C) 2015, IBM Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 *USA.
 */

#ifndef _HYPERCALL_DEBUG_H
#define _HYPERCALL_DEBUG_H

#include <osv/debug.hh>

/*
 * dprint: Selective debug printing
 *
 * Use an OR combination of DBG_* as dbgcat in dprint*(dbgcat,...)
 * to assign debug messages to categories:
 *
 * dbgcat	Debug message belongs to category
 * ----------------------------------------------------------------------------
 * DBG_ON	    Always on, for really important events or error conditions
 * DBG_HOST	    Host
 * DBG_GUEST    Guest
 * DBG_DEV  Device
 * DBG_IBV  Verbs
 * DBG_ATTR Attributes
 * DBG_BUS      Bus events
 * DBG_ALL	    All categories above
 */
#define DBG_ON 0x00000001
#define DBG_HOST 0x00000002
#define DBG_GUEST 0x00000004
#define DBG_DEV 0x00000008
#define DBG_IBV 0x00000010
#define DBG_ATTR 0x00000020
#define DBG_BUS 0x00000040
#define DBG_ALL (DBG_ON | DBG_HOST | DBG_GUEST | DBG_DEV | DBG_IBV | DBG_ATTR | DBG_BUS)

/*
 * Set DPRINT_MASK to tailor your debugging needs:
 *
 * DPRINT_MASK value		Enables debug messages for
 * ---------------------------------------------------------------------
 * DBG_ON			Important events / error conditions only
 *				(minimum number of debug messages)
 * OR-ed combination of DBG_*	Selective debugging
 * DBG_KT|DBG_ON		Kernel threads
 * DBG_ALL			All categories
 */
#define DPRINT_MASK DBG_ALL

#if DPRINT_MASK > 0

/**
 * dprint - Selective debug print for process, SoftIRQ or HardIRQ context
 *
 * Debug print with selectable debug categories,
 * starting with header
 * - "( pid /cpu) __func__" for process context
 * - "( irq /cpu) __func__" for IRQ context
 *
 * @dbgcat	: Set of debug categories (OR-ed combination of DBG_* above),
 *		  to which this debug message is assigned.
 * @fmt		: printf compliant format string
 * @args	: printf compliant argument list
 */
#define dprint(dbgcat, fmt, args...)                                           \
    do {                                                                   \
        if ((dbgcat) & DPRINT_MASK) {                                  \
            debug("hypercall debug: %s " fmt,                 \
            __func__,  \
            ##args);                               \
        }                                                              \
    } while (0)

#endif

#endif
