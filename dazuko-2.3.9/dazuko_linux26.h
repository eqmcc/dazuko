/* Dazuko Linux. Allow Linux 2.6 file access control for 3rd-party applications.
   Written by John Ogness <dazukocode@ogness.net>

   Copyright (c) 2003, 2004, 2005, 2006 H+BEDV Datentechnik GmbH
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

#ifndef DAZUKO_LINUX26_H
#define DAZUKO_LINUX26_H

#include <linux/module.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
#include <asm/semaphore.h>
#else
#include <linux/semaphore.h>
#endif

#define	DEVICE_NAME		"dazuko"

#define XP_ERROR_PERMISSION	-EPERM
#define XP_ERROR_INTERRUPT	-EINTR
#define XP_ERROR_BUSY		-EBUSY
#define XP_ERROR_FAULT		-EFAULT
#define XP_ERROR_INVALID	-EINVAL
#define XP_ERROR_NODEVICE	-ENODEV


struct xp_daemon_id
{
	int			pid;
	int			tgid;
	struct file		*file;
	struct task_struct	*current_p;
	struct files_struct	*files;
};

struct xp_mutex
{
	struct semaphore mutex;
};

struct xp_atomic
{
	atomic_t atomic;
};

struct xp_file_struct
{
	int full_filename_length;
	char *full_filename;
	int free_full_filename;
	struct dentry *dentry;
	int dput_dentry;
	char *buffer;
	int free_page_buffer;
	struct nameidata *nd;
	struct vfsmount *vfsmount;
	int mntput_vfsmount;
	struct inode *inode;
};

struct xp_queue
{
	wait_queue_head_t queue;
};

struct xp_rwlock
{
	rwlock_t rwlock;
};

#endif
