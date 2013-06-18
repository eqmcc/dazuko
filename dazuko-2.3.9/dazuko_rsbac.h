/* Dazuko RSBAC. Allow RSBAC Linux file access control for 3rd-party applications.
   Written by John Ogness <dazukocode@ogness.net>

   Copyright (c) 2004, 2005, 2006 H+BEDV Datentechnik GmbH
   Copyright (c) 2007 Avira GmbH
   All rights reserved.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation; either version 2
   of the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#ifndef DAZUKO_RSBAC_H
#define DAZUKO_RSBAC_H

#if CONFIG_MODVERSIONS==1
#define MODVERSIONS
#include <linux/modversions.h>
#endif

#include <linux/kernel.h>
#include <linux/version.h>

#ifdef MODULE
#include <linux/module.h>
#endif

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) ((a)*65536+(b)*256+(c))
#endif

#include <linux/slab.h>
#include <asm/atomic.h>

#ifdef CONFIG_SMP
#ifndef __SMP__
#define __SMP__
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#ifdef __SMP__
#include <asm/smplock.h>
#endif
#else
#include <asm/semaphore.h>
#endif


#define	DEVICE_NAME		"dazuko"

#define XP_ERROR_PERMISSION	-EPERM
#define XP_ERROR_INTERRUPT	-EINTR
#define XP_ERROR_BUSY		-EBUSY
#define XP_ERROR_FAULT		-EFAULT
#define XP_ERROR_INVALID	-EINVAL


struct xp_daemon_id
{
	int			pid;
	struct file		*file;
	struct task_struct	*current_p;
	struct files_struct	*files;
};

struct xp_mutex
{
	struct semaphore	mutex;
};

struct xp_atomic
{
	atomic_t	atomic;
};

struct xp_file_struct
{
	int			full_filename_length;	/* length of filename */
	char			*full_filename;		/* kernelspace filename with full path */
	int			free_full_filename;	/* flag to clean up full_filename */
	struct dentry		*dentry;		/* used to get inode */
};

struct xp_queue
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	wait_queue_head_t queue;
#else
	struct wait_queue *queue;
#endif
};

struct xp_rwlock
{
	rwlock_t	rwlock;
};

#endif
