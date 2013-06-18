/* Dazuko Linux. Allow Linux file access control for 3rd-party applications.
   Written by John Ogness <dazukocode@ogness.net>

   Copyright (c) 2002, 2003, 2004, 2005 H+BEDV Datentechnik GmbH
   Copyright (c) 2006, 2007 Avira GmbH
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

#include "dazuko_linux.h"
#include "dazuko_core.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#include "dazuko_linux26_device_def.h"

#ifdef USE_CONFIG_H
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/vermagic.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#ifdef DEVFS_SUPPORT
#include <linux/devfs_fs_kernel.h>
#endif
#include <linux/device.h>
#if !defined(USE_TRYTOFREEZEVOID)
#include <linux/suspend.h>
#endif
#ifdef LINUX_USE_FREEZER_H
#include <linux/freezer.h>
#endif
#include <asm/uaccess.h>
#include <linux/ptrace.h>
#include <asm/unistd.h>
#ifdef LINUX_USE_SYSCALLS_H
#include <linux/syscalls.h>
#endif
#include <asm/pgtable.h>
#ifdef SYSCALL_TABLE_READONLY
#include <asm/page.h>
#include <asm/cacheflush.h>
#endif

#else

#ifdef DEVFS_SUPPORT
#include <linux/devfs_fs_kernel.h>
#endif

#endif

#include <asm/unistd.h>


#ifndef __NR_close
#define __NR_close 6
#endif


#ifndef DAZUKO_DM
#define DAZUKO_DM 0
#endif


#define CHROOT_EVENT_STRING "chroot:"
#define CHROOT_EVENT_LENGTH 7


#ifndef USE_CHROOT
#ifndef WITH_LOCAL_DPATH
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
extern char * __d_path(struct dentry *, struct vfsmount *, struct dentry *, struct vfsmount *, char *, int);
#endif
#endif
#endif


#ifdef HIDDEN_SCT
void **sys_call_table;
extern asmlinkage long sys_exit(int error_code);
#else
extern void *sys_call_table[];
#endif



#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)

#define USERPTR __user

ssize_t linux_dazuko_device_read(struct file *, char __user *, size_t, loff_t *);
ssize_t linux_dazuko_device_write(struct file *, const char __user *, size_t, loff_t *);
int linux_dazuko_device_open(struct inode *, struct file *);
int linux_dazuko_device_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long param);
int linux_dazuko_device_release(struct inode *, struct file *);

#ifndef WITHOUT_UDEV
#ifdef USE_CLASS
static struct class *dazuko_class = NULL;
#else
static struct class_simple *dazuko_class = NULL;
#endif
#endif

#else

#define USERPTR

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
int linux_dazuko_device_read(struct file *file, char *buffer, size_t length, loff_t *pos);
int linux_dazuko_device_write(struct file *file, const char *buffer, size_t length, loff_t *pos);
#else
ssize_t linux_dazuko_device_read(struct file *file, char *buffer, size_t length, loff_t *pos);
ssize_t linux_dazuko_device_write(struct file *file, const char *buffer, size_t length, loff_t *pos);
#endif
int linux_dazuko_device_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long param);
int linux_dazuko_device_open(struct inode *inode, struct file *file);
int linux_dazuko_device_release(struct inode *inode, struct file *file);

#endif


extern struct xp_atomic active;


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
static struct vfsmount	*orig_rootmnt = NULL;
#endif

static struct dentry	*orig_root = NULL;
static int		dev_major = -1;


#if defined(ON_OPEN_SUPPORT)
	static asmlinkage long (*original_sys_open)(const char USERPTR *filename, int flags, int mode);
	static asmlinkage long (*original_sys_dup)(unsigned int filedes);
#endif

#if defined(ON_OPEN_SUPPORT) || defined(ON_CLOSE_SUPPORT) || defined(ON_CLOSE_MODIFIED_SUPPORT)
	static asmlinkage long (*original_sys_dup2)(unsigned int oldfd, unsigned int newfd);
#endif

#if defined(ON_CLOSE_SUPPORT) || defined(ON_CLOSE_MODIFIED_SUPPORT)
	static asmlinkage long (*original_sys_close)(unsigned int fd);
#endif

#ifdef ON_EXEC_SUPPORT
	static asmlinkage int (*original_sys_execve)(struct pt_regs regs);
#endif

#ifdef ON_UNLINK_SUPPORT
	static asmlinkage long (*original_sys_unlink)(const char USERPTR *pathname);
#endif

#ifdef ON_RMDIR_SUPPORT
	static asmlinkage long (*original_sys_rmdir)(const char USERPTR *pathname);
#endif


static struct file_operations	fops = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	.owner		= THIS_MODULE,
	.read		= linux_dazuko_device_read,
	.write		= linux_dazuko_device_write,
	.ioctl		= linux_dazuko_device_ioctl,
	.open		= linux_dazuko_device_open,
	.release	= linux_dazuko_device_release,
#else
	read: linux_dazuko_device_read,		/* read */
	write: linux_dazuko_device_write,	/* write */
	ioctl: linux_dazuko_device_ioctl,	/* ioctl */
	open: linux_dazuko_device_open,		/* open */
	release: linux_dazuko_device_release,	/* release */
#endif
	};


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)

/* The following code is taken directly from Linux in the file:
   include/linux/sched.h */

#ifndef __wait_event_interruptible
#define __wait_event_interruptible(wq, condition, ret)		 \
do {								 \
	struct wait_queue __wait;				 \
								 \
	__wait.task = current;					 \
	add_wait_queue(&wq, &__wait);				 \
	for (;;) {						 \
		current->state = TASK_INTERRUPTIBLE;		 \
		mb();						 \
		if (condition)					 \
			break;					 \
		if (!signal_pending(current)) {			 \
			schedule();				 \
			continue;				 \
		}						 \
		ret = -ERESTARTSYS;				 \
		break;						 \
	}							 \
	current->state = TASK_RUNNING;				 \
	remove_wait_queue(&wq, &__wait);			 \
} while (0)
#endif

#ifndef wait_event_interruptible
#define wait_event_interruptible(wq, condition)			 \
({								 \
	int __ret = 0;						 \
	if (!(condition))					 \
		__wait_event_interruptible(wq, condition, __ret);\
	__ret;							 \
})
#define wait_event(wq, condition)				 \
({								 \
	int __ret = 0;						 \
	if (!(condition))					 \
		__wait_event_interruptible(wq, condition, __ret);\
	__ret;							 \
})
#endif

#endif


/* mutex */

inline void xp_init_mutex(struct xp_mutex *mutex)
{
	#ifdef init_MUTEX
		init_MUTEX(&(mutex->mutex));
	#else
		sema_init(&(mutex->mutex), 1);
	#endif
}

inline void xp_down(struct xp_mutex *mutex)
{
	down(&(mutex->mutex));
}

inline void xp_up(struct xp_mutex *mutex)
{
	up(&(mutex->mutex));
}

inline void xp_destroy_mutex(struct xp_mutex *mutex)
{
}


/* read-write lock */

inline void xp_init_rwlock(struct xp_rwlock *rwlock)
{
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
		rwlock_init(&(rwlock->rwlock));
	#else
		rwlock->rwlock = RW_LOCK_UNLOCKED;
	#endif
}

inline void xp_write_lock(struct xp_rwlock *rwlock)
{
	write_lock(&(rwlock->rwlock));
}

inline void xp_write_unlock(struct xp_rwlock *rwlock)
{
	write_unlock(&(rwlock->rwlock));
}

inline void xp_read_lock(struct xp_rwlock *rlock)
{
	read_lock(&(rlock->rwlock));
}

inline void xp_read_unlock(struct xp_rwlock *rlock)
{
	read_unlock(&(rlock->rwlock));
}

inline void xp_destroy_rwlock(struct xp_rwlock *rwlock)
{
}


/* wait-notify queue */

inline int xp_init_queue(struct xp_queue *queue)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	init_waitqueue_head(&(queue->queue));
#else
	queue = NULL;
#endif

	return 0;
}

inline int xp_wait_until_condition(struct xp_queue *queue, int (*cfunction)(void *), void *cparam, int allow_interrupt)
{
	/* wait until cfunction(cparam) != 0 (condition is true) */
	int	ret = 0;

	if (allow_interrupt)
	{
		while (1)
		{
			ret = wait_event_interruptible(queue->queue, cfunction(cparam) != 0);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	#if defined (USE_TRYTOFREEZEVOID)
			if (try_to_freeze() == 0)
				break;
	#else
			if (current->flags & PF_FREEZE)
			{
				refrigerator(PF_FREEZE);
			}
			else
			{
				break;
			}
	#endif
#else
			break;
#endif
		}
	}
	else
	{
		wait_event(queue->queue, cfunction(cparam) != 0);
	}

	return ret;
}

inline int xp_notify(struct xp_queue *queue)
{
	wake_up(&(queue->queue));
	return 0;
}

inline int xp_destroy_queue(struct xp_queue *queue)
{
	return 0;
}


/* memory */

inline void* xp_malloc(size_t size)
{
	return kmalloc(size, GFP_KERNEL);
}

inline int xp_free(void *ptr)
{
	kfree(ptr);
	return 0;
}

inline int xp_copyin(const void *user_src, void *kernel_dest, size_t size)
{
	return copy_from_user(kernel_dest, user_src, size);
}

inline int xp_copyout(const void *kernel_src, void *user_dest, size_t size)
{
	return copy_to_user(user_dest, kernel_src, size);
}

inline int xp_verify_user_writable(const void *user_ptr, size_t size)
{
	#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
		return verify_area(VERIFY_WRITE, user_ptr, size);
	#else
		return 0;
	#endif
}

inline int xp_verify_user_readable(const void *user_ptr, size_t size)
{
	#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
		return verify_area(VERIFY_READ, user_ptr, size);
	#else
		return 0;
	#endif
}


/* path attribute */

inline int xp_is_absolute_path(const char *path)
{
	if (path[0] == '/')
		return 1;

#ifdef USE_CHROOT
	if (dazuko_strlen(path) >= CHROOT_EVENT_LENGTH)
	{
		if (memcmp(CHROOT_EVENT_STRING, path, CHROOT_EVENT_LENGTH) == 0)
			return 1;
	}
#endif

	return 0;
}


/* atomic */

inline int xp_atomic_set(struct xp_atomic *atomic, int value)
{
	atomic_set(&(atomic->atomic), value);
	return 0;
}

inline int xp_atomic_inc(struct xp_atomic *atomic)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#ifdef MODULE
	if (atomic == &active)
		MOD_INC_USE_COUNT;
#endif
#endif

	atomic_inc(&(atomic->atomic));
	return 0;
}

inline int xp_atomic_dec(struct xp_atomic *atomic)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#ifdef MODULE
	if (atomic == &active)
		MOD_DEC_USE_COUNT;
#endif
#endif

	atomic_dec(&(atomic->atomic));
	return 0;
}

inline int xp_atomic_read(struct xp_atomic *atomic)
{
	return atomic_read(&(atomic->atomic));
}


/* file structure */

#ifdef WITH_LOCAL_DPATH
/* This code is taken directy from:
   linux-2.6.0/fs/dcache.c
   because __d_path is no longer exported.
 */
/**
 * d_path - return the path of a dentry
 * @dentry: dentry to report
 * @vfsmnt: vfsmnt to which the dentry belongs
 * @root: root dentry
 * @rootmnt: vfsmnt to which the root dentry belongs
 * @buffer: buffer to return value in
 * @buflen: buffer length
 *
 * Convert a dentry into an ASCII path name. If the entry has been deleted
 * the string " (deleted)" is appended. Note that this is ambiguous.
 *
 * Returns the buffer or an error code if the path was too long.
 *
 * "buflen" should be positive. Caller holds the dcache_lock.
 */
static char * __d_path( struct dentry *dentry, struct vfsmount *vfsmnt,
			struct dentry *root, struct vfsmount *rootmnt,
			char *buffer, int buflen)
{
	char * end = buffer+buflen;
	char * retval;
	int namelen;

	*--end = '\0';
	buflen--;
	if (!IS_ROOT(dentry) && d_unhashed(dentry)) {
		buflen -= 10;
		end -= 10;
		if (buflen < 0)
			goto Elong;
		memcpy(end, " (deleted)", 10);
	}

	if (buflen < 1)
		goto Elong;
	/* Get '/' right */
	retval = end-1;
	*retval = '/';

	for (;;) {
		struct dentry * parent;

		if (dentry == root && vfsmnt == rootmnt)
			break;
		if (dentry == vfsmnt->mnt_root || IS_ROOT(dentry)) {
			/* Global root? */
			if (vfsmnt->mnt_parent == vfsmnt)
				goto global_root;
			dentry = vfsmnt->mnt_mountpoint;
			vfsmnt = vfsmnt->mnt_parent;
			continue;
		}
		parent = dentry->d_parent;
		prefetch(parent);
		namelen = dentry->d_name.len;
		buflen -= namelen + 1;
		if (buflen < 0)
			goto Elong;
		end -= namelen;
		memcpy(end, dentry->d_name.name, namelen);
		*--end = '/';
		retval = end;
		dentry = parent;
	}

	return retval;

global_root:
	namelen = dentry->d_name.len;
	buflen -= namelen;
	if (buflen < 0)
		goto Elong;
	retval -= namelen-1;	/* hit the slash */
	memcpy(retval, dentry->d_name.name, namelen);
	return retval;
Elong:
	return ERR_PTR(-ENAMETOOLONG);
}
#endif

/* Copied 1:1 from Linux kernel source kernel/exit.c */
/* Why is this not exported? put_files_struct is exported! */
static inline struct files_struct *dazuko_get_files_struct(struct task_struct *task)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	struct files_struct *files;

	task_lock(task);
	files = task->files;
	if (files != NULL)
		atomic_inc(&files->count);
	task_unlock(task);

	return files;
#else
	return task->files;
#endif
}

static inline void dazuko_put_files_struct(struct files_struct *fs)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	put_files_struct(fs);
#endif
}

static int dazuko_get_filename_dentry(struct xp_file_struct *xfs, int follow_symlinks, const char *local_filename, int user_ptr)
{
	/* We get the appropriate structures in order
	 * to acquire the inode and store them in the
	 * dazuko_file_struct structure. */

	const char	*filename = NULL;
	int		putname_filename = 0;
	int		filename_length = 0;
	int		rc = 0;

	/* make sure we really need to get the filename */
	if (user_ptr)
	{
		/* grab filename from filename cache */
		filename = (char *)getname(local_filename);

		/* make sure it is a valid name */
		if (IS_ERR(filename))
		{
			DPRINT(("dazuko: dazuko_get_filename_dentry: getname failed\n"));
			filename = NULL;
			return 0;
		}

		/* the name will need to be put back */
		putname_filename = 1;
	}
	else
	{
		filename = local_filename;
	}

	filename_length = dazuko_strlen(filename);

	#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	{
		dazuko_bzero(&(xfs->nd), sizeof(struct nameidata));

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
		if (path_lookup(filename, follow_symlinks ? LOOKUP_FOLLOW : 0, &(xfs->nd)))
		{
			DPRINT(("dazuko: dazuko_get_filename_dentry: path_lookup failed\n"));
			goto dentry_exit;
		}

		/* the nameidata will need to be released */
		xfs->path_release_nd = 1;
#else
		/* initialize nameidata structure for finding file data */
		if (!path_init(filename, (follow_symlinks ? LOOKUP_FOLLOW : 0) | LOOKUP_POSITIVE, &(xfs->nd)))
			goto dentry_exit;

		if (!xfs->path_release_nd)
		{
			/* find file data and fill it in nameidata structure */
			if (path_walk(filename, &(xfs->nd)))  /* !=0 -> error */
				goto dentry_exit;

			/* the nameidata will need to be released */
			xfs->path_release_nd = 1;
		}
#endif

		/* get a local copy of the dentry to make kernel version
		 * compatibility code eaiser to read */

		/* make sure we don't already have a dentry */
		if (!xfs->dput_dentry)
		{
			xfs->dentry = dget(xfs->nd.dentry);

			/* the dentry will need to be put back */
			xfs->dput_dentry = 1;
		}
	}
	#else
	{
		if (!xfs->dput_dentry)
		{
			xfs->dentry = lookup_dentry(filename, NULL, (follow_symlinks ? LOOKUP_FOLLOW : 0));
			if (IS_ERR(xfs->dentry))
			{
				xfs->dentry = NULL;
				goto dentry_exit;
			}

			/* the dentry will need to be put back */
			xfs->dput_dentry = 1;
		}
	}
	#endif

	/* check if this file has no inode */
	if (xfs->dentry->d_inode == NULL)
	{
		DPRINT(("dazuko: dazuko_get_filename_dentry: inode is NULL\n"));
		goto dentry_exit;
	}
	else
	{
		/* if we made it this far, we got the inode */
		rc = 1;
	}

dentry_exit:
	if (putname_filename)
		putname(filename);

	DPRINT(("dazuko: dazuko_get_filename_dentry returning %d\n", rc));
	return rc;
}

/* inspired by include/linux/file.h (Linux 2.6) */
static inline struct file * dazuko_fcheck_files(struct files_struct *files, unsigned int fd, int lock)
{
	struct file	*file = NULL;

	#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	{
		if (lock)
			spin_lock(&files->file_lock);
	}
	#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	{
		if (lock)
			read_lock(&files->file_lock);
	}
	#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
{
	struct fdtable	*fdt = files_fdtable(files);

	if (fdt->fd != NULL)
	{
		if (fd < fdt->max_fds)
			file = rcu_dereference(fdt->fd[fd]);
	}
}
#else
	if (files->fd != NULL)
	{
		if (fd < files->max_fds)
			file = files->fd[fd];
	}
#endif

	#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	{
		if (lock)
			spin_unlock(&files->file_lock);
	}
	#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	{
		if (lock)
			read_unlock(&files->file_lock);
	}
	#endif

	return file;
}

static int dazuko_get_fd_dentry(struct xp_file_struct *xfs)
{
	struct files_struct	*files = NULL;
	struct file		*file = NULL;

	files = dazuko_get_files_struct(current);

	if (files != NULL)
	{
		#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
		{
			spin_lock(&files->file_lock);
		}
		#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
		{
			read_lock(&files->file_lock);
		}
		#endif

		file = dazuko_fcheck_files(files, xfs->fd, 0);
		if (file != NULL)
		{
			if (file->f_dentry != NULL)
			{
				xfs->dentry = dget(file->f_dentry);
				xfs->dput_dentry = 1;

				#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
				{
					if (file->f_vfsmnt != NULL)
					{
						xfs->vfsmount = mntget(file->f_vfsmnt);
						xfs->mntput_vfsmount = 1;
					}
					else
					{
						dput(xfs->dentry);
						xfs->dentry = NULL;
						xfs->dput_dentry = 0;
					}
				}
				#endif
			}
		}

		#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
		{
			spin_unlock(&files->file_lock);
		}
		#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
		{
			read_unlock(&files->file_lock);
		}
		#endif

		dazuko_put_files_struct(files);
	}

	/* check if we got the dentry */
	if (xfs->dentry == NULL)
		return 0;

	/* check if this file has no inode */
	if (xfs->dentry->d_inode == NULL)
		return 0;

	return 1;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
static char * __d_path(struct dentry *dentry, struct dentry *root, char *buffer, int buflen)
{
	/* Copy of d_path from linux/dcache.c but using
	 * a given root instead of the current root. */

	char * end = buffer+buflen;
	char * retval;

	*--end = '\0';
	buflen--;
	if (dentry->d_parent != dentry && list_empty(&dentry->d_hash)) {
		buflen -= 10;
		end -= 10;
		memcpy(end, " (deleted)", 10);
	}

	/* Get '/' right */
	retval = end-1;
	*retval = '/';

	for (;;) {
		struct dentry * parent;
		int namelen;

		if (dentry == root)
			break;
		dentry = dentry->d_covers;
		parent = dentry->d_parent;
		if (dentry == parent)
			break;
		namelen = dentry->d_name.len;
		buflen -= namelen + 1;
		if (buflen < 0)
			break;
		end -= namelen;
		memcpy(end, dentry->d_name.name, namelen);
		*--end = '/';
		retval = end;
		dentry = parent;
	}
	return retval;
}
#endif

static int dazuko_get_full_filename(struct xp_file_struct *xfs)
{
	/* Get the filename with the full path appended
	 * to the beginning. */

	char		*temp;
	struct dentry	*root;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	struct vfsmount	*rootmnt;
#endif

#ifdef USE_CHROOT
	int chrooted = 0;
#endif

	/* check if we need to allocate a buffer */
	if (!xfs->free_page_buffer)
	{
		/* get pre-requisites for d_path function */
		xfs->buffer = (char *)__get_free_page(GFP_USER);

		/* the buffer will need to be freed */
		xfs->free_page_buffer = 1;
	}

	root = dget(orig_root);

	#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	{
		/* make sure we don't already have a vfsmount */
		if (!xfs->mntput_vfsmount)
		{
			xfs->vfsmount = mntget(xfs->nd.mnt);

			/* the vfsmount will need to be put back */
			xfs->mntput_vfsmount = 1;
		}

		/* build new filename with path included, using temp */

		rootmnt = mntget(orig_rootmnt);

#ifdef USE_CHROOT
		temp = d_path(xfs->dentry, xfs->vfsmount, xfs->buffer, PAGE_SIZE);
		task_lock(current);
		if (orig_root != current->fs->root)
			chrooted = 1;
		task_unlock(current);
#else
		spin_lock(&dcache_lock);
		temp = __d_path(xfs->dentry, xfs->vfsmount, root, rootmnt, xfs->buffer, PAGE_SIZE);
		spin_unlock(&dcache_lock);
#endif

		mntput(rootmnt);
	}
	#else
	{
		/* build new filename with path included, using temp */

		temp = __d_path(xfs->dentry, root, xfs->buffer, PAGE_SIZE);
	}
	#endif

	dput(root);

	/* make sure we really got a new filename */
	if (temp == NULL)
		return 0;

	/* make sure we don't already have a full_filename */
	if (!xfs->free_full_filename)
	{
		xfs->full_filename_length = dazuko_strlen(temp);

#ifdef USE_CHROOT
		if (chrooted)
			xfs->full_filename_length += CHROOT_EVENT_LENGTH;
#endif
		xfs->full_filename = (char *)xp_malloc(xfs->full_filename_length + 1);
		if (!xfs->full_filename)
			return 0;

		/* the char array will need to be freed */
		xfs->free_full_filename = 1;

#ifdef USE_CHROOT
		if (chrooted)
		{
			memcpy(xfs->full_filename, CHROOT_EVENT_STRING, CHROOT_EVENT_LENGTH + 1);
			memcpy(xfs->full_filename + CHROOT_EVENT_LENGTH, temp, xfs->full_filename_length - CHROOT_EVENT_LENGTH + 1);
		}
		else
#endif
		memcpy(xfs->full_filename, temp, xfs->full_filename_length + 1);
	}

	/* we have a filename with the full path */

	return 1;
}

static inline int dazuko_fill_file_struct_cleanup(struct dazuko_file_struct *dfs)
{
	/* Delete all the flagged structures from the
	 * given dazuko_file_struct and reset all critical
	 * values back to 0. */

	if (dfs->extra_data == NULL)
		return 0;

	#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	{
		if (dfs->extra_data->mntput_vfsmount)
		{
			mntput(dfs->extra_data->vfsmount);
			dfs->extra_data->mntput_vfsmount = 0;
		}
	}
	#endif

	if (dfs->extra_data->free_page_buffer)
	{
		free_page((unsigned long)dfs->extra_data->buffer);
		dfs->extra_data->free_page_buffer = 0;
	}

	if (dfs->extra_data->dput_dentry)
	{
		dput(dfs->extra_data->dentry);
		dfs->extra_data->dput_dentry = 0;
	}

	#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	{
		if (dfs->extra_data->path_release_nd)
		{
			path_release(&(dfs->extra_data->nd));
			dfs->extra_data->path_release_nd = 0;
		}
	}
	#endif

	return 0;
}

inline int xp_fill_file_struct(struct dazuko_file_struct *dfs)
{
	struct dazuko_file_listnode	*listnode;
	int				follow_symlinks = 0;
	int				error = -1;
	int				loopcount = 0;
	char				*freeparentpath = NULL;
	char				*parentpath = NULL;
	char				*rawfilename = NULL;
	int				i;

	if (dfs == NULL)
		return error;

	/* check if filenames have already been filled in */
	if (dfs->aliases != NULL)
		return 0;

	if (dfs->extra_data == NULL)
		return error;

	/* make sure we can get an inode */
	while (1)
	{
		loopcount++;

		if (dfs->extra_data->user_filename != NULL)
		{
			if (!dazuko_get_filename_dentry(dfs->extra_data, follow_symlinks, dfs->extra_data->user_filename, 1))
			{
				/* we will try to build a "fake" name from the parent directory */

				if (freeparentpath != NULL)
				{
					/* This needs to be put if we are in the second loop
					 * because the parent was a link. */
					putname(freeparentpath);
				}
				freeparentpath = getname(dfs->extra_data->user_filename);
				/* make sure it is a valid name */
				if (IS_ERR(freeparentpath))
				{
					freeparentpath = NULL;
					DPRINT(("dazuko: xp_fill_file_struct: getname failed\n"));
					break;
				}

				parentpath = freeparentpath;

				i = dazuko_strlen(parentpath);
				if (i == 0)
					break;

				while (i > 0)
				{
					if (parentpath[i] == '/')
					{
						rawfilename = parentpath + i + 1;
						parentpath[i] = 0;
						break;
					}

					i--;
				}
				if (i == 0)
				{
					if (parentpath[i] == '/')
					{
						rawfilename = parentpath + 1;
						parentpath = "/";
					}
					else
					{
						rawfilename = parentpath;
						parentpath = ".";
					}
				}

				if (!dazuko_get_filename_dentry(dfs->extra_data, follow_symlinks, parentpath, 0))
				{
					putname(freeparentpath);
					freeparentpath = NULL;
					DPRINT(("dazuko: dazuko_get_filename_dentry failed for %s\n", parentpath));
					break;
				}
			}
		}
		else
		{
			if (!dazuko_get_fd_dentry(dfs->extra_data))
			{
				DPRINT(("dazuko: dazuko_get_fd_dentry failed\n"));
				break;
			}
			else
			{
				/* make sure we don't loop a 2nd time */
				loopcount++;
			}
		}

		/* make sure we can get the full path */
		if (!dazuko_get_full_filename(dfs->extra_data)) 
		{
			DPRINT(("dazuko: dazuko_get_full_filename failed\n"));
			break;
		}

		if (freeparentpath != NULL)
		{
			/* we are working with a "fake" name */

			DPRINT(("dazuko: building full path at loop=%d, we have %s\n", loopcount, dfs->extra_data->full_filename));

			parentpath = dfs->extra_data->full_filename;
			i =  dazuko_strlen(rawfilename);

			dfs->extra_data->full_filename = (char *)xp_malloc(dfs->extra_data->full_filename_length + 1 + i + 1);
			if (dfs->extra_data->full_filename == NULL)
			{
				/* put things back how they were and get out */
				dfs->extra_data->full_filename = parentpath;
				break;
			}

			/* copy parent path */
			memcpy(dfs->extra_data->full_filename, parentpath, dfs->extra_data->full_filename_length);

			/* possibly copy "/" */
			if (dfs->extra_data->full_filename[dfs->extra_data->full_filename_length - 1] != '/')
			{
				dfs->extra_data->full_filename[dfs->extra_data->full_filename_length] = '/';
				dfs->extra_data->full_filename_length++;
			}

			/* copy filename */
			memcpy(dfs->extra_data->full_filename + dfs->extra_data->full_filename_length, rawfilename, i + 1);
			dfs->extra_data->full_filename_length += i;

			DPRINT(("dazuko: constructed full filename: %s\n", dfs->extra_data->full_filename));

			/* free allocated parent path */
			xp_free(parentpath);
		}
		else
		{
			dfs->file_p.size = dfs->extra_data->dentry->d_inode->i_size;
			dfs->file_p.set_size = 1;
			dfs->file_p.uid = dfs->extra_data->dentry->d_inode->i_uid;
			dfs->file_p.set_uid = 1;
			dfs->file_p.gid = dfs->extra_data->dentry->d_inode->i_gid;
			dfs->file_p.set_gid = 1;
			dfs->file_p.mode = dfs->extra_data->dentry->d_inode->i_mode;
			dfs->file_p.set_mode = 1;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
			dfs->file_p.device_type = dfs->extra_data->dentry->d_inode->i_rdev;
			dfs->file_p.set_device_type = 1;
#else
			dfs->file_p.device_type = dfs->extra_data->dentry->d_inode->i_dev;
			dfs->file_p.set_device_type = 1;
#endif
		}

		DPRINT(("dazuko: we have full path at loop=%d, %s\n", loopcount, dfs->extra_data->full_filename));

		if (S_ISREG(dfs->extra_data->dentry->d_inode->i_mode))
		{
			DPRINT(("dazuko: inode is regular file\n"));
			dfs->file_p.type = DAZUKO_REGULAR;
			dfs->file_p.set_type = 1;
		}
		else if (S_ISLNK(dfs->extra_data->dentry->d_inode->i_mode))
		{
			DPRINT(("dazuko: inode is symlink\n"));
			dfs->file_p.type = DAZUKO_LINK;
			dfs->file_p.set_type = 1;
		}
		else if (S_ISDIR(dfs->extra_data->dentry->d_inode->i_mode))
		{
			DPRINT(("dazuko: inode is a directory\n"));
			dfs->file_p.type = DAZUKO_DIRECTORY;
			dfs->file_p.set_type = 1;
		}

		listnode = (struct dazuko_file_listnode *)xp_malloc(sizeof(struct dazuko_file_listnode));
		if (listnode == NULL)
			break;

		dazuko_bzero(listnode, sizeof(struct dazuko_file_listnode));

		listnode->filename = dfs->extra_data->full_filename;
		listnode->filename_length = dfs->extra_data->full_filename_length;  /* the string length */

		dfs->extra_data->free_full_filename = 0;
		dfs->extra_data->full_filename = NULL;
		dfs->extra_data->full_filename_length = 0;

		if (dfs->aliases == NULL)
		{
			listnode->next = dfs->aliases;
			dfs->aliases = listnode;
		}
		else
		{
			listnode->next = dfs->aliases->next;
			dfs->aliases->next = listnode;
		}

		/* we successfully got the file information */
		error = 0;

		if (!follow_symlinks && dfs->file_p.set_type && dfs->file_p.type == DAZUKO_LINK && loopcount < 2)
		{
			/* this is a link, we will grab the real path now */

			follow_symlinks = 1;

			/* clean up because we are going to fill it again */
			dazuko_fill_file_struct_cleanup(dfs);
		}
		else
		{
			/* we've grabbed the real path (or we already have 2 paths), so we are done */

			break;
		}
	}

	if (freeparentpath != NULL)
		putname(freeparentpath);

	dazuko_fill_file_struct_cleanup(dfs);

	DPRINT(("dazuko: xp_fill_file_struct returning %d\n", error));

	return error;
}

static int dazuko_file_struct_cleanup(struct dazuko_file_struct **dfs)
{
	struct dazuko_file_listnode	*cur;

	if (dfs == NULL)
		return 0;

	if (*dfs == NULL)
		return 0;

	while ((*dfs)->aliases != NULL)
	{
		cur = (*dfs)->aliases;
		(*dfs)->aliases = cur->next;

		if (cur->filename != NULL)
			xp_free(cur->filename);

		xp_free(cur);
	}

	if ((*dfs)->extra_data != NULL)
		xp_free((*dfs)->extra_data);

	xp_free(*dfs);

	*dfs = NULL;

	return 0;
}


/* daemon id */

static inline int check_parent(struct task_struct *parent, struct task_struct *child)
{
	struct task_struct	*ts = child;

	if (parent == NULL || child == NULL)
		return -1;

	while (1)
	{
		if (ts == parent)
			return 0;

#ifdef TASKSTRUCT_USES_PARENT
		if (ts->parent == NULL)
			break;

		if (ts == ts->parent)
			break;

		ts = ts->parent;
#else
		if (ts->p_pptr == NULL)
			break;

		if (ts == ts->p_pptr)
			break;

		ts = ts->p_pptr;
#endif
	}

	return -1;
}

inline int xp_id_compare(struct xp_daemon_id *id1, struct xp_daemon_id *id2, int check_related)
{
	if (id1 == NULL || id2 == NULL)
		return DAZUKO_DIFFERENT;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	/* If file's are available we do a special
	 * check ("file"'s are only used by daemons).
	 * Here we allow threads to look like one
	 * instance, if they pass around the handle.
	 * Note: this is a Linux-only "hack" */
	if (id1->file != NULL && id2->file != NULL)
	{
		if (id1->tgid == id2->tgid && id1->files == id2->files && id1->file == id2->file)
			return DAZUKO_SAME;
	}
#endif

	if (id1->pid == id2->pid && id1->current_p == id2->current_p && id1->files == id2->files)
		return DAZUKO_SAME;

	if (check_related)
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
		/* Same thread id and same file descriptors,
		 * looks like they could be the same process...
		 * We will treat two threads of the same process
		 * as the same (for relation checks). This is
		 * useful for the Trusted Application Framework,
		 * if we trust one thread, we can trust them all.*/
		if (id1->tgid == id2->tgid && id1->files == id2->files)
		{
			/* Two different threads of the same process will have different current pointers,
			 * but if process ids match, current pointers must too. */

			if (id1->pid == id2->pid && id1->current_p == id2->current_p)
				return DAZUKO_SAME;

			if (id1->pid != id2->pid && id1->current_p != id2->current_p)
				return DAZUKO_SAME;
		}
#endif

		if (check_parent(id1->current_p, id2->current_p) == 0)
		{
			return DAZUKO_CHILD;
		}
		else if (id1->pid == id2->pid || id1->current_p == id2->current_p || id1->files == id2->files)
		{
			return DAZUKO_SUSPICIOUS;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
		else if (id1->tgid == id2->tgid)
		{
			return DAZUKO_SUSPICIOUS;
		}
#endif
	}

	return DAZUKO_DIFFERENT;
}

inline int xp_id_free(struct xp_daemon_id *id)
{
	xp_free(id);

	return 0;
}

inline struct xp_daemon_id* xp_id_copy(struct xp_daemon_id *id)
{
	struct xp_daemon_id	*ptr;

	if (id == NULL)
		return NULL;

	ptr = (struct xp_daemon_id *)xp_malloc(sizeof(struct xp_daemon_id));

	if (ptr != NULL)
	{
		ptr->pid = id->pid;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
		ptr->tgid = id->tgid;
#endif
		ptr->file = id->file;
		ptr->current_p = id->current_p;
		ptr->files = id->files;
	}

	return ptr;
}


/* event */

int xp_set_event_properties(struct event_properties *event_p, struct xp_daemon_id *xp_id)
{
	event_p->pid = xp_id->pid;
	event_p->set_pid = 1;

	return 0;
}


/* cache settings */

int xp_init_cache(unsigned long ttl)
{
	return -1;
}


/* include/exclude paths */

int xp_set_path(const char *path, int type)
{
	return 0;
}


/* system calls */

#if defined(ON_OPEN_SUPPORT)
asmlinkage long linux_dazuko_sys_open(const char USERPTR *filename, int flags, int mode)
{
	/* The kernel wants to open the given filename
	 * with the given flags and mode. The dazuko_file_struct
	 * is used to handle the tricky job of cleaning
	 * up the many pieces of memory that may or may
	 * not be allocated. */

	struct dazuko_file_struct	*dfs = NULL;
	int				error = 0;
	int				fd;
	int				check_error = 0;
	struct event_properties		event_p;
	struct xp_daemon_id		xp_id;

	xp_id.pid = current->pid;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	xp_id.tgid = current->tgid;
#endif
	xp_id.file = NULL;
	xp_id.current_p = current;
	xp_id.files = dazuko_get_files_struct(current);

	check_error = dazuko_check_access(DAZUKO_ON_OPEN, 1, &xp_id, NULL);

	if (xp_id.files != NULL)
		dazuko_put_files_struct(xp_id.files);

	if (!check_error)
	{
		dazuko_bzero(&event_p, sizeof(event_p));
		event_p.flags = flags;
		event_p.set_flags = 1;
		event_p.mode = mode;
		event_p.set_mode = 1;
		event_p.pid = current->pid;
		event_p.set_pid = 1;
		event_p.uid = current->uid;
		event_p.set_uid = 1;

		dfs = (struct dazuko_file_struct *)xp_malloc(sizeof(struct dazuko_file_struct));
		if (dfs != NULL)
		{
			dazuko_bzero(dfs, sizeof(struct dazuko_file_struct));

			dfs->extra_data = (struct xp_file_struct *)xp_malloc(sizeof(struct xp_file_struct));
			if (dfs->extra_data != NULL)
			{
				dazuko_bzero(dfs->extra_data, sizeof(struct xp_file_struct));

				dfs->extra_data->user_filename = filename;

				error = dazuko_process_access(DAZUKO_ON_OPEN, dfs, &event_p, NULL);

				dazuko_file_struct_cleanup(&dfs);
			}
			else
			{
				xp_free(dfs);
				dfs = NULL;
			}
		}
	}

	if (error)
	{
		/* access should be blocked */

		fd = -1;
	}
	else
	{
		/* call the standard open function */
		fd = original_sys_open(filename, flags, mode);
	}

	return fd;
}

asmlinkage long linux_dazuko_sys_dup(unsigned int filedes)
{
	struct dazuko_file_struct	*dfs = NULL;
	struct event_properties		event_p;
	struct xp_daemon_id		xp_id;
	int				error = 0;
	int				check_error = 0;

	xp_id.pid = current->pid;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	xp_id.tgid = current->tgid;
#endif
	xp_id.file = NULL;
	xp_id.current_p = current;
	xp_id.files = dazuko_get_files_struct(current);

	check_error = dazuko_check_access(DAZUKO_ON_OPEN, 1, &xp_id, NULL);

	if (!check_error)
	{
		dazuko_bzero(&event_p, sizeof(event_p));

		if (dazuko_fcheck_files(xp_id.files, filedes, 1) != NULL)
		{
			event_p.pid = current->pid;
			event_p.set_pid = 1;
			event_p.uid = current->uid;
			event_p.set_uid = 1;

			dfs = (struct dazuko_file_struct *)xp_malloc(sizeof(struct dazuko_file_struct));
			if (dfs != NULL)
			{
				dazuko_bzero(dfs, sizeof(struct dazuko_file_struct));

				dfs->extra_data = (struct xp_file_struct *)xp_malloc(sizeof(struct xp_file_struct));
				if (dfs->extra_data != NULL)
				{
					dazuko_bzero(dfs->extra_data, sizeof(struct xp_file_struct));

					dfs->extra_data->fd = filedes;

					error = dazuko_process_access(DAZUKO_ON_OPEN, dfs, &event_p, NULL);

					dazuko_file_struct_cleanup(&dfs);
				}
				else
				{
					xp_free(dfs);
					dfs = NULL;
				}
			}
		}
		else
		{
			check_error = -1;
		}
	}

	if (xp_id.files != NULL)
		dazuko_put_files_struct(xp_id.files);

	if (error)
	{
		/* access should be blocked */

		error = -EPERM;
	}
	else
	{
		/* call the standard open function */
		error = original_sys_dup(filedes);
	}

	return error;
}
#endif

#if defined(ON_OPEN_SUPPORT) || defined(ON_CLOSE_SUPPORT) || defined(ON_CLOSE_MODIFIED_SUPPORT)
asmlinkage long linux_dazuko_sys_dup2(unsigned int oldfd, unsigned int newfd)
{
	struct dazuko_file_struct	*dfs = NULL;
	struct event_properties		open_event_p;
	struct xp_daemon_id		xp_id;
	int				error = 0;
	int				check_error = 0;
#if defined(ON_CLOSE_SUPPORT) || defined(ON_CLOSE_MODIFIED_SUPPORT)
	struct event_properties		close_event_p;
	int				will_close_newfd = 0;
#endif

	xp_id.pid = current->pid;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	xp_id.tgid = current->tgid;
#endif
	xp_id.file = NULL;
	xp_id.current_p = current;
	xp_id.files = dazuko_get_files_struct(current);

	check_error = dazuko_check_access(DAZUKO_ON_OPEN, 1, &xp_id, NULL);

	if (!check_error)
	{
		dazuko_bzero(&open_event_p, sizeof(open_event_p));

		if (oldfd != newfd && dazuko_fcheck_files(xp_id.files, oldfd, 1) != NULL)
		{
			open_event_p.pid = current->pid;
			open_event_p.set_pid = 1;
			open_event_p.uid = current->uid;
			open_event_p.set_uid = 1;

			dfs = (struct dazuko_file_struct *)xp_malloc(sizeof(struct dazuko_file_struct));
			if (dfs != NULL)
			{
				dazuko_bzero(dfs, sizeof(struct dazuko_file_struct));

				dfs->extra_data = (struct xp_file_struct *)xp_malloc(sizeof(struct xp_file_struct));
				if (dfs->extra_data != NULL)
				{
					dazuko_bzero(dfs->extra_data, sizeof(struct xp_file_struct));

					dfs->extra_data->fd = oldfd;

					error = dazuko_process_access(DAZUKO_ON_OPEN, dfs, &open_event_p, NULL);

					dazuko_file_struct_cleanup(&dfs);
				}
				else
				{
					xp_free(dfs);
					dfs = NULL;
				}
			}
		}
		else
		{
			check_error = -1;
		}
	}

	if (error)
	{
		/* access should be blocked */

		error = -EPERM;
	}
	else
	{
		#if defined(ON_CLOSE_SUPPORT) || defined(ON_CLOSE_MODIFIED_SUPPORT)
		if (dazuko_fcheck_files(xp_id.files, newfd, 1) != NULL)
		{
			will_close_newfd = 1;
		}
		#endif

		/* call the standard open function */
		error = original_sys_dup2(oldfd, newfd);

		#if defined(ON_CLOSE_SUPPORT) || defined(ON_CLOSE_MODIFIED_SUPPORT)
		{
			if (!check_error)
			{
				if (error >= 0 && will_close_newfd)
				{
					dazuko_bzero(&close_event_p, sizeof(close_event_p));

					close_event_p.pid = current->pid;
					close_event_p.set_pid = 1;
					close_event_p.uid = current->uid;
					close_event_p.set_uid = 1;

					dfs = (struct dazuko_file_struct *)xp_malloc(sizeof(struct dazuko_file_struct));
					if (dfs != NULL)
					{
						dazuko_bzero(dfs, sizeof(struct dazuko_file_struct));

						dfs->extra_data = (struct xp_file_struct *)xp_malloc(sizeof(struct xp_file_struct));
						if (dfs->extra_data != NULL)
						{
							dazuko_bzero(dfs->extra_data, sizeof(struct xp_file_struct));

							dfs->extra_data->fd = newfd;

							dazuko_process_access(DAZUKO_ON_CLOSE, dfs, &close_event_p, NULL);

							dazuko_file_struct_cleanup(&dfs);
						}
						else
						{
							xp_free(dfs);
							dfs = NULL;
						}
					}
				}
			}
		}
		#endif
	}

	if (xp_id.files != NULL)
		dazuko_put_files_struct(xp_id.files);

	return error;
}
#endif

#if defined(ON_CLOSE_SUPPORT) || defined(ON_CLOSE_MODIFIED_SUPPORT)
asmlinkage long	linux_dazuko_sys_close(unsigned int fd)
{
	/* The kernel wants to close the given file
	 * descriptor. */

	struct dazuko_file_struct	*dfs = NULL;
	int				error = 0;
	int				check_error = 0;
	struct event_properties		event_p;
	struct xp_daemon_id		xp_id;

	xp_id.pid = current->pid;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	xp_id.tgid = current->tgid;
#endif
	xp_id.file = NULL;
	xp_id.current_p = current;
	xp_id.files = dazuko_get_files_struct(current);

	check_error = dazuko_check_access(DAZUKO_ON_CLOSE, 1, &xp_id, NULL);

	if (!check_error && dazuko_fcheck_files(xp_id.files, fd, 1) != NULL)
	{
		dazuko_bzero(&event_p, sizeof(event_p));

		event_p.pid = current->pid;
		event_p.set_pid = 1;
		event_p.uid = current->uid;
		event_p.set_uid = 1;

		dfs = (struct dazuko_file_struct *)xp_malloc(sizeof(struct dazuko_file_struct));
		if (dfs != NULL)
		{
			dazuko_bzero(dfs, sizeof(struct dazuko_file_struct));

			dfs->extra_data = (struct xp_file_struct *)xp_malloc(sizeof(struct xp_file_struct));
			if (dfs->extra_data != NULL)
			{
				dazuko_bzero(dfs->extra_data, sizeof(struct xp_file_struct));

				dfs->extra_data->fd = fd;

				check_error = xp_fill_file_struct(dfs);
			}
			else
			{
				xp_free(dfs);
				dfs = NULL;
			}
		}
	}

	if (xp_id.files != NULL)
		dazuko_put_files_struct(xp_id.files);

	error = original_sys_close(fd);

	if (dfs != NULL)
	{
		if (!check_error)
		{
			dazuko_process_access(DAZUKO_ON_CLOSE, dfs, &event_p, NULL);
		}

		dazuko_file_struct_cleanup(&dfs);
	}

	return error;
}
#endif

#ifdef ON_EXEC_SUPPORT

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
typedef int (*do_execve_call_t)(char *filename, char __user *__user *argv, char __user *__user *envp, struct pt_regs *regs);

static do_execve_call_t XXX_do_execve = (do_execve_call_t) DO_EXECVE_ADDR;
#endif

asmlinkage int linux_dazuko_sys_execve(struct pt_regs regs)
{
	/* The kernel wants to execute the given file.
	 * Because the given structure contains stack
	 * address information, we can't simply call
	 * the default standard execve. Instead we
	 * have to manually inline the standard execve
	 * call. */

	struct dazuko_file_struct	*dfs = NULL;
	char				*filename;
	int				error = 0;
	int				check_error = 0;
	struct event_properties		event_p;
	struct xp_daemon_id		xp_id;
	struct slot_list		*sl = NULL;

	xp_id.pid = current->pid;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	xp_id.tgid = current->tgid;
#endif
	xp_id.file = NULL;
	xp_id.current_p = current;
	xp_id.files = dazuko_get_files_struct(current);

	check_error = dazuko_check_access(DAZUKO_ON_EXEC, 0, &xp_id, &sl);

	if (xp_id.files != NULL)
		dazuko_put_files_struct(xp_id.files);

	if (!check_error)
	{
		dfs = (struct dazuko_file_struct *)xp_malloc(sizeof(struct dazuko_file_struct));
		if (dfs)
		{
			dazuko_bzero(dfs, sizeof(struct dazuko_file_struct));

			dfs->extra_data = (struct xp_file_struct *)xp_malloc(sizeof(struct xp_file_struct));
			if (dfs->extra_data != NULL)
			{
				dazuko_bzero(dfs->extra_data, sizeof(struct xp_file_struct));

				dfs->extra_data->user_filename = (char *)regs.ebx;

				dazuko_bzero(&event_p, sizeof(event_p));
				event_p.pid = current->pid;
				event_p.set_pid = 1;
				event_p.uid = current->uid;
				event_p.set_uid = 1;

				error = dazuko_process_access(DAZUKO_ON_EXEC, dfs, &event_p, sl);

				dazuko_file_struct_cleanup(&dfs);
			}
			else
			{
				xp_free(dfs);
				dfs = NULL;
			}
		}
	}

	if (error)
	{
		return error;
	}

	/* call the standard execve function */

	/* We cannot simply call the original version of execvc
	 * because the parameter contains stack information and
	 * the call will push the execvc call onto a new stack
	 * level and seg fault. :( */

	/* The following code only works on i386 machines.
	 * It is directly copied from Linux in the file:
	 * arch/i386/kernel/process.c */

	#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	{
		filename = getname((char __user *) regs.ebx);
		error = PTR_ERR(filename);
		if (IS_ERR(filename))
			goto out;
		error = XXX_do_execve(filename, (char __user * __user *) regs.ecx, (char __user * __user *) regs.edx, &regs);
		if (error == 0)
		{
			#ifndef CONFIG_UTRACE
				task_lock(current);
				current->ptrace &= ~PT_DTRACE;
				task_unlock(current);
			#endif
			/* Make sure we don't return using sysenter.. */
			set_thread_flag(TIF_IRET);
		}
		putname(filename);
out:
		return error;
	}
	#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	{
		filename = getname((char *) regs.ebx);
		error = PTR_ERR(filename);
		if (IS_ERR(filename))
		{
			filename = NULL;
			goto out;
		}
		error = do_execve(filename, (char **) regs.ecx, (char **) regs.edx, &regs);
		if (error == 0)
			current->ptrace &= ~PT_DTRACE;
		putname(filename);
out:
		return error;
	}
	#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,2,20)
	{
		#ifdef __SMP__
			lock_kernel();
		#endif
		filename = getname((char *) regs.ebx);
		error = PTR_ERR(filename);
		if (IS_ERR(filename))
		{
			filename = NULL;
			goto out;
		}
		error = do_execve(filename, (char **) regs.ecx, (char **) regs.edx, &regs);
		if (error == 0)
			current->ptrace &= ~PT_DTRACE;
		putname(filename);
out:
		#ifdef __SMP__
			unlock_kernel();
		#endif
		return error;
	}
	#else
	{
		#ifdef __SMP__
			lock_kernel();
		#endif
		filename = getname((char *) regs.ebx);
		error = PTR_ERR(filename);
		if (IS_ERR(filename))
		{
			filename = NULL;
			goto out;
		}
		error = do_execve(filename, (char **) regs.ecx, (char **) regs.edx, &regs);
		if (error == 0)
			current->flags &= ~PF_DTRACE;
		putname(filename);
out:
		#ifdef __SMP__
			unlock_kernel();
		#endif
		return error;
	}
	#endif
}
#endif

static inline int linux_dazuko_sys_generic(int event, const char USERPTR *user_pathname, int daemon_is_allowed)
{
	struct dazuko_file_struct	*dfs = NULL;
	int				error = 0;
	int				check_error = 0;
	struct event_properties		event_p;
	struct xp_daemon_id		xp_id;
	struct slot_list		*sl = NULL;

	xp_id.pid = current->pid;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	xp_id.tgid = current->tgid;
#endif
	xp_id.file = NULL;
	xp_id.current_p = current;
	xp_id.files = dazuko_get_files_struct(current);

	check_error = dazuko_check_access(event, daemon_is_allowed, &xp_id, &sl);

	if (xp_id.files != NULL)
		dazuko_put_files_struct(xp_id.files);

	if (!check_error)
	{
		dfs = (struct dazuko_file_struct *)xp_malloc(sizeof(struct dazuko_file_struct));
		if (dfs)
		{
			dazuko_bzero(dfs, sizeof(struct dazuko_file_struct));

			dfs->extra_data = (struct xp_file_struct *)xp_malloc(sizeof(struct xp_file_struct));
			if (dfs->extra_data != NULL)
			{
				dazuko_bzero(dfs->extra_data, sizeof(struct xp_file_struct));

				dfs->extra_data->user_filename = user_pathname;

				dazuko_bzero(&event_p, sizeof(event_p));
				event_p.pid = current->pid;
				event_p.set_pid = 1;
				event_p.uid = current->uid;
				event_p.set_uid = 1;

				error = dazuko_process_access(event, dfs, &event_p, sl);

				dazuko_file_struct_cleanup(&dfs);
			}
			else
			{
				xp_free(dfs);
				dfs = NULL;
			}
		}
	}

	return error;
}

#ifdef ON_UNLINK_SUPPORT
asmlinkage long linux_dazuko_sys_unlink(const char USERPTR *pathname)
{
	int	error;

	error = linux_dazuko_sys_generic(DAZUKO_ON_UNLINK, pathname, 1);

	if (error)
		return error;

	return original_sys_unlink(pathname);
}
#endif

#ifdef ON_RMDIR_SUPPORT
asmlinkage long linux_dazuko_sys_rmdir(const char USERPTR *pathname)
{
	int	error;

	error = linux_dazuko_sys_generic(DAZUKO_ON_RMDIR, pathname, 1);

	if (error)
		return error;

	return original_sys_rmdir(pathname);
}
#endif


/* system hook */

#ifdef HIDDEN_SCT
static void** dazuko_get_sct(void)
{
	unsigned char	**p;

#ifdef SYS_CALL_TABLE_ADDR
	p = (unsigned char **)SYS_CALL_TABLE_ADDR;

	if (p != NULL)
	{
		if (p[__NR_close] == (unsigned char *)sys_close)
		{
			return (void **)p;
		}
	}
#else
	unsigned long	ptr;
	extern int	loops_per_jiffy;

	for (ptr=(unsigned long)&loops_per_jiffy ; ptr<(unsigned long)&boot_cpu_data ; ptr+=sizeof(void *))
	{
		p = (unsigned char **)ptr;
		if (p[__NR_close] == (unsigned char *)sys_close)
		{
			return (void **)p;
		}
	}
#endif

	return NULL;
}
#endif

static inline void dazuko_lock_current(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	task_lock(current);
#endif
}

static inline void dazuko_unlock_current(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	task_unlock(current);
#endif
}

#ifdef PERFORM_SCT_CHECK
static int dazuko_is_address_writable(unsigned long address)
{
	pgd_t *pgd = pgd_offset_k(address);
#ifdef PUD_SIZE
	pud_t *pud;
#endif
	pmd_t *pmd;
	pte_t *pte;

	if (pgd_none(*pgd))
		return -1;
#ifdef PUD_SIZE
	pud = pud_offset(pgd, address);
	if (pud_none(*pud))
		return -1;
	pmd = pmd_offset(pud, address);
#else
	pmd = pmd_offset(pgd, address);
#endif
	if (pmd_none(*pmd))
		return -1;

	if (pmd_large(*pmd))
		pte = (pte_t *)pmd;
	else
		pte = pte_offset_kernel(pmd, address);

	if (!pte || !pte_present(*pte))
		return -1;

	return pte_write(*pte) ? 1 : 0;
}
#endif

#define DAZUKO_HOOK(syscall_func) do \
{ \
	original_sys_##syscall_func = sys_call_table[__NR_##syscall_func]; \
	sys_call_table[__NR_##syscall_func] = linux_dazuko_sys_##syscall_func; \
	DPRINT(("dazuko: hooked sys_" #syscall_func "\n")); \
} \
while (0)

inline int xp_sys_hook(void)
{
#ifdef PERFORM_SCT_CHECK
	int syscall_writable;
#endif

	/* Called insmod when inserting the module. */

#ifdef HIDDEN_SCT
	sys_call_table = dazuko_get_sct();
	if (sys_call_table == NULL)
	{
		xp_print("dazuko: panic (sys_call_table == NULL)\n");
		return -1;
	}
#endif

	/* Make sure we have a valid task_struct. */

	if (current == NULL)
	{
		xp_print("dazuko: panic (current == NULL)\n");
		return -1;
	}
	dazuko_lock_current();
	if (current->fs == NULL)
	{
		dazuko_unlock_current();
		xp_print("dazuko: panic (current->fs == NULL)\n");
		return -1;
	}
	if (current->fs->root == NULL)
	{
		dazuko_unlock_current();
		xp_print("dazuko: panic (current->fs->root == NULL)\n");
		return -1;
	}
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	{
		if (current->fs->rootmnt == NULL)
		{
			dazuko_unlock_current();
			xp_print("dazuko: panic (current->fs->rootmnt == NULL)\n");
			return -1;
		}
	}
	#endif

	dazuko_unlock_current();

	/* register the dazuko device */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	dev_major = register_chrdev(DAZUKO_DM, DEVICE_NAME, &fops);
	if (dev_major < 0)
	{
		xp_print("dazuko: unable to register device, err=%d\n", dev_major);
		return dev_major;
	}

#ifdef DEVFS_SUPPORT
	devfs_mk_cdev(MKDEV(dev_major, 0), S_IFCHR | S_IRUSR | S_IWUSR, DEVICE_NAME);
#endif

#ifndef WITHOUT_UDEV
#ifdef USE_CLASS
	dazuko_class = class_create(THIS_MODULE, DEVICE_NAME);
#if defined (CLASS_class_device_create_2_6_15)
	class_device_create(dazuko_class, NULL, MKDEV(dev_major, 0), NULL, DEVICE_NAME);
#elif defined (CLASS_device_create_2_6_26)
	device_create(dazuko_class, NULL, MKDEV(dev_major, 0), DEVICE_NAME);
#else
	class_device_create(dazuko_class, MKDEV(dev_major, 0), NULL, DEVICE_NAME);
#endif
#else
	dazuko_class = class_simple_create(THIS_MODULE, DEVICE_NAME);
	class_simple_device_add(dazuko_class, MKDEV(dev_major, 0), NULL, DEVICE_NAME);
#endif
#endif

#else
	#ifdef DEVFS_SUPPORT
		dev_major = devfs_register_chrdev(0, DEVICE_NAME, &fops);
		devfs_register(NULL, DEVICE_NAME, DEVFS_FL_DEFAULT,
			dev_major, 0, S_IFCHR | S_IRUSR | S_IWUSR,
			&fops, NULL);
	#else
		dev_major = register_chrdev(DAZUKO_DM, DEVICE_NAME, &fops);
	#endif
	if (dev_major < 0)
	{
		dazuko_unlock_current();
		xp_print("dazuko: unable to register device chrdev, err=%d\n", dev_major);
		return dev_major;
	}
#endif

#ifdef USE_CHROOT
	xp_print("dazuko: info: using chroot events for chroot'd processes\n");
#endif
#if defined(CONFIG_SMP) && defined(WITH_LOCAL_DPATH)
	xp_print("dazuko: warning: using local __dpath() dangerous for SMP kernels\n");
#endif

	/* Grab the current root. This is assumed to be the real.
	 * If it is not the real root, we could have problems
	 * looking up filenames. */

	dazuko_lock_current();

	#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	{
		read_lock(&current->fs->lock);
		orig_rootmnt = current->fs->rootmnt;
	}
	#endif

	orig_root = current->fs->root;

	#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
		read_unlock(&current->fs->lock);
	#endif

	dazuko_unlock_current();

	/* do a file syncronization on all devices (IMPORTANT!) and replace system calls */
	#ifdef __SMP__
		lock_kernel();
	#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	fsync_dev(0);
#endif

#ifdef SYSCALL_TABLE_READONLY
	syscall_writable = dazuko_is_address_writable((unsigned long) sys_call_table);
	if (syscall_writable < 0)
	{
		xp_print("dazuko: unable to determine if syscall table is readonly, assuming it is\n");
	}
	if (syscall_writable <= 0)
	{
		/* unprotect the syscall table */
		change_page_attr(virt_to_page(sys_call_table), 1, PAGE_KERNEL);
		global_flush_tlb();
	}
#endif

#ifdef PERFORM_SCT_CHECK
	syscall_writable = dazuko_is_address_writable((unsigned long) sys_call_table);
	if (syscall_writable != 1)
	{
		xp_print("dazuko: warning: assuming syscall table can be modified\n");
	}
#endif

#if defined(ON_OPEN_SUPPORT)
	DAZUKO_HOOK(open);
	DAZUKO_HOOK(dup);
#endif
#if defined(ON_OPEN_SUPPORT) || defined(ON_CLOSE_SUPPORT) || defined(ON_CLOSE_MODIFIED_SUPPORT)
	DAZUKO_HOOK(dup2);
#endif
	
#if defined(ON_CLOSE_SUPPORT) || defined(ON_CLOSE_MODIFIED_SUPPORT)
	DAZUKO_HOOK(close);
#endif

#ifdef ON_EXEC_SUPPORT
	DAZUKO_HOOK(execve);
#endif

#ifdef ON_UNLINK_SUPPORT
	DAZUKO_HOOK(unlink);
#endif

#ifdef ON_RMDIR_SUPPORT
	DAZUKO_HOOK(rmdir);
#endif

#ifdef SYSCALL_TABLE_READONLY
	/* protect the syscall table */
	if (syscall_writable <= 0)
	{
		change_page_attr(virt_to_page(sys_call_table), 1, PAGE_KERNEL_RO);
		global_flush_tlb();
	}
#endif

	#ifdef __SMP__
		unlock_kernel();
	#endif
	/* done syncing and replacing */

	/* initialization complete */

	return 0;
}

#define DAZUKO_UNHOOK(syscall_func) do \
{ \
	if (sys_call_table[__NR_##syscall_func] != linux_dazuko_sys_##syscall_func) \
		xp_print("dazuko: " #syscall_func " system call has been changed (system may be left in an unstable state!)\n"); \
	sys_call_table[__NR_##syscall_func] = original_sys_##syscall_func; \
	DPRINT(("dazuko: unhooked sys_" #syscall_func "\n")); \
} \
while (0)

inline int xp_sys_unhook(void)
{
#ifdef SYSCALL_TABLE_READONLY
	int syscall_writable;
#endif

	/* Called by rmmod when removing the module. */

	/* do a file syncronization on all devices (IMPORTANT!) and replace system calls */
	#ifdef __SMP__
		lock_kernel();
	#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	fsync_dev(0);
#endif

#ifdef SYSCALL_TABLE_READONLY
	syscall_writable = dazuko_is_address_writable((unsigned long) sys_call_table);

	if (syscall_writable <= 0)
	{
		/* unprotect the syscall table */
		change_page_attr(virt_to_page(sys_call_table), 1, PAGE_KERNEL);
		global_flush_tlb();
	}
#endif

#if defined(ON_OPEN_SUPPORT)
	DAZUKO_UNHOOK(open);
	DAZUKO_UNHOOK(dup);
#endif
#if defined(ON_OPEN_SUPPORT) || defined(ON_CLOSE_SUPPORT) || defined(ON_CLOSE_MODIFIED_SUPPORT)
	DAZUKO_UNHOOK(dup2);
#endif

#if defined(ON_CLOSE_SUPPORT) || defined(ON_CLOSE_MODIFIED_SUPPORT)
	DAZUKO_UNHOOK(close);
#endif

#ifdef ON_EXEC_SUPPORT
	DAZUKO_UNHOOK(execve);
#endif

#ifdef ON_UNLINK_SUPPORT
	DAZUKO_UNHOOK(unlink);
#endif

#ifdef ON_RMDIR_SUPPORT
	DAZUKO_UNHOOK(rmdir);
#endif

#ifdef SYSCALL_TABLE_READONLY
	/* protect the syscall table */
	if (syscall_writable <= 0)
	{
		change_page_attr(virt_to_page(sys_call_table), 1, PAGE_KERNEL_RO);
		global_flush_tlb();
	}
#endif

	#ifdef __SMP__
		unlock_kernel();
	#endif
	/* done syncing and replacing */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	unregister_chrdev(dev_major, DEVICE_NAME);

#ifdef DEVFS_SUPPORT
	devfs_remove(DEVICE_NAME);
#endif

#ifndef WITHOUT_UDEV
#ifdef USE_CLASS
#if defined (CLASS_device_create_2_6_26)
		device_destroy(dazuko_class, MKDEV(dev_major, 0));
#else
		class_device_destroy(dazuko_class, MKDEV(dev_major, 0));
#endif
		class_destroy(dazuko_class);
#else
		class_simple_device_remove(MKDEV(dev_major, 0));
		class_simple_destroy(dazuko_class);
#endif
#endif

#else
	#ifdef DEVFS_SUPPORT
		devfs_unregister_chrdev(dev_major, DEVICE_NAME);
		devfs_unregister(devfs_find_handle(NULL, DEVICE_NAME, dev_major, 0, DEVFS_SPECIAL_CHR, 0));
	#else
		unregister_chrdev(dev_major, DEVICE_NAME);
	#endif
#endif

	return 0;
}


/* output */

int xp_print(const char *fmt, ...)
{
	va_list args;
	char *p;
	size_t size = 1024;
	int length;

	p = (char *)xp_malloc(size);
	if (p == NULL)
		return -1;

	length = dazuko_strlen(KERN_INFO);

	memcpy(p, KERN_INFO, length);

	va_start(args, fmt);
	dazuko_vsnprintf(p + length, size - length, fmt, args);
	va_end(args);

	p[size-1] = 0;

	printk(p);

	xp_free(p);

	return 0;
}


/* ioctl's */

int linux_dazuko_device_open(struct inode *inode, struct file *file)
{
	DPRINT(("dazuko: linux_dazuko_device_open() [%d]\n", current->pid));

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
int linux_dazuko_device_read(struct file *file, char *buffer, size_t length, loff_t *pos)
#else
ssize_t linux_dazuko_device_read(struct file *file, char *buffer, size_t length, loff_t *pos)
#endif
{
	/* Reading from the dazuko device simply
	 * returns the device number. This is to
	 * help out the daemon. */

	char	tmp[20];
	size_t	dev_major_len;

	DPRINT(("dazuko: linux_dazuko_device_read() [%d]\n", current->pid));

	/* only one read is allowed */

	if (*pos != 0)
		return 0;

	if (dev_major < 0)
		return XP_ERROR_NODEVICE;

	/* print dev_major to a string
	 * and get length (with terminator) */
	dazuko_bzero(tmp, sizeof(tmp));

	dev_major_len = dazuko_snprintf(tmp, sizeof(tmp), "%d", dev_major) + 1;

	if (tmp[sizeof(tmp)-1] != 0)
	{
		xp_print("dazuko: failing device_read, device number overflow for dameon %d (dev_major=%d)\n", current->pid, dev_major);
		return XP_ERROR_FAULT;
	}

	if (length < dev_major_len)
		return XP_ERROR_INVALID;

	/* copy dev_major string to userspace */
	if (xp_copyout(tmp, buffer, dev_major_len) != 0)
		return XP_ERROR_FAULT;

	*pos += dev_major_len;

	return dev_major_len;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
int linux_dazuko_device_write(struct file *file, const char *buffer, size_t length, loff_t *pos)
{
	/* multiple device_write entries are not allowed
	 * with older kernels, so we force compat1 mode */

	return length;
}
#else
ssize_t linux_dazuko_device_write(struct file *file, const char *buffer, size_t length, loff_t *pos)
{
	struct xp_daemon_id	xp_id;
	char			tmpbuffer[32];
	int			size;
	ssize_t			ret;

	size = length;
	if (length >= sizeof(tmpbuffer))
		size = sizeof(tmpbuffer) - 1;

	/* copy request pointer string to kernelspace */
	if (xp_copyin(buffer, tmpbuffer, size) != 0)
		return XP_ERROR_FAULT;

	tmpbuffer[size] = 0;

	xp_id.pid = current->pid;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	xp_id.tgid = current->tgid;
#endif
	xp_id.file = file;
	xp_id.current_p = current;
	xp_id.files = dazuko_get_files_struct(current);

	if (dazuko_handle_user_request(tmpbuffer, &xp_id) == 0)
	{
		/* we say the full length was written (even if it is not true) */
		ret = length;
	}
	else
	{
		ret = XP_ERROR_INTERRUPT;
	}

	if (xp_id.files != NULL)
		dazuko_put_files_struct(xp_id.files);

	return ret;
}
#endif

int linux_dazuko_device_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long param)
{
	/* A daemon uses this function to interact with
	 * the kernel. A daemon can set scanning parameters,
	 * give scanning response, and get filenames to scan. */

	struct xp_daemon_id	xp_id;
	int			error = 0;

	if (param == 0)
	{
		xp_print("dazuko: error: linux_dazuko_device_ioctl(..., 0)\n");
		return XP_ERROR_INVALID;
	}

	xp_id.pid = current->pid;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	xp_id.tgid = current->tgid;
#endif
	xp_id.file = file;
	xp_id.current_p = current;
	xp_id.files = dazuko_get_files_struct(current);

	error = dazuko_handle_user_request_compat1((void *)param, _IOC_NR(cmd), &xp_id);

	if (xp_id.files != NULL)
		dazuko_put_files_struct(xp_id.files);

	if (error != 0)
	{
		/* general error occurred */

		return XP_ERROR_PERMISSION;
	}

	return error;
}

int linux_dazuko_device_release(struct inode *inode, struct file *file)
{
	struct xp_daemon_id	xp_id;
	int			ret;

	DPRINT(("dazuko: dazuko_device_release() [%d]\n", current->pid));

	xp_id.pid = current->pid;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
	xp_id.tgid = current->tgid;
#endif
	xp_id.file = file;
	xp_id.current_p = current;
	xp_id.files = dazuko_get_files_struct(current);

	ret = dazuko_unregister_daemon(&xp_id);

	if (xp_id.files != NULL)
		dazuko_put_files_struct(xp_id.files);

	return ret;
}


/* init/exit */

static int __init linux_dazuko_init(void)
{
	return dazuko_init();
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0)
static void __exit linux_dazuko_exit(void)
#else
void linux_dazuko_exit(void)
#endif
{
	dazuko_exit();
}


#ifdef MODULE
        
MODULE_AUTHOR("John Ogness <dazukocode@ogness.net>");
MODULE_DESCRIPTION("allow 3rd-party file access control");
#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#else
static const char __module_license[] __attribute__((section(".modinfo"))) = "license=GPL";
#endif   


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)

MODULE_INFO(vermagic, VERMAGIC_STRING);

security_initcall(linux_dazuko_init);
module_exit(linux_dazuko_exit);
#else

int init_module(void)
{
	return linux_dazuko_init();
}

void cleanup_module(void)
{
	linux_dazuko_exit();
}

EXPORT_NO_SYMBOLS;

#endif


#else

module_init(linux_dazuko_init);
module_exit(linux_dazuko_exit);
/* module_init(int linux_dazuko_init(void)); */
/* module_exit(void linux_dazuko_exit(void)); */

#endif
