/*************************************************** */
/* Rule Set Based Access Control                     */
/* Implementation of the Access Control Decision     */
/* Facility (ADF) - Dazuko Malware Scan              */
/* File: rsbac/adf/daz/daz_main.c                    */
/*                                                   */
/* Author and (c) 1999-2004: Amon Ott <ao@rsbac.org> */
/* Copyright (c) 2004-2005 H+BEDV Datentechnik GmbH  */
/* Copyright (c) 2006-2007 Avira GmbH                */
/* Written by John Ogness <dazukocode@ogness.net>    */
/*                                                   */
/* Last modified: 2/Nov/2006                         */
/*************************************************** */

/* Dazuko RSBAC. Allow RSBAC Linux file access control for 3rd-party applications.

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

#include "dazuko_rsbac.h"
#include "dazuko_core.h"

#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/random.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#include <linux/vermagic.h>
#endif

#include <linux/string.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#include <linux/syscalls.h>
#endif
#include <asm/uaccess.h>
#include <rsbac/types.h>
#include <rsbac/aci.h>
#include <rsbac/adf.h>
#include <rsbac/adf_main.h>
#include <rsbac/debug.h>
#include <rsbac/error.h>
#include <rsbac/helpers.h>
#include <rsbac/getname.h>
#include <rsbac/net_getname.h>
#include <rsbac/rkmem.h>
#include <rsbac/proc_fs.h>

/************************************************* */
/*           Global Variables                      */
/************************************************* */

#if defined(CONFIG_DEVFS_FS) || LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#include <linux/devfs_fs_kernel.h>
#endif

ssize_t linux_dazuko_device_read(struct file *file, char *buffer, size_t length, loff_t *pos);
ssize_t linux_dazuko_device_write(struct file *file, const char *buffer, size_t length, loff_t *pos);
int linux_dazuko_device_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long param);
int linux_dazuko_device_open(struct inode *inode, struct file *file);
int linux_dazuko_device_release(struct inode *inode, struct file *file);

extern struct xp_atomic active;

static int			dev_major = -1;

static struct file_operations	fops = {
					read: linux_dazuko_device_read,		/* read */
					write: linux_dazuko_device_write,	/* write */
					ioctl: linux_dazuko_device_ioctl,	/* ioctl */
					open: linux_dazuko_device_open,		/* open */
					release: linux_dazuko_device_release,	/* release */
				};

/************************************************* */
/*          Internal Help functions                */
/************************************************* */

#if defined(CONFIG_RSBAC_DAZ_CACHE)
static int reset_scanned(struct rsbac_fs_file_t file)
  {
    union rsbac_attribute_value_t i_attr_val1;
    union rsbac_target_id_t       i_tid;

    /* reset scanned status for file */
    i_tid.file=file;
    i_attr_val1.daz_scanned = DAZ_unscanned;
    if(rsbac_set_attr(DAZ,
                      T_FILE,
                      i_tid,
                      A_daz_scanned,
                      i_attr_val1))
      {
        printk(KERN_WARNING "reset_scanned(): rsbac_set_attr() returned error!\n");
        return(-RSBAC_EWRITEFAILED);
      }
    /* reset scanner flag for file */
    i_attr_val1.daz_scanner = FALSE;
    if(rsbac_set_attr(DAZ,
                      T_FILE,
                      i_tid,
                      A_daz_scanner,
                      i_attr_val1))
      {
        printk(KERN_WARNING "reset_scanned(): rsbac_set_attr() returned error!\n");
        return(-RSBAC_EWRITEFAILED);
      }
    return(0);
  }
#else
static inline int reset_scanned(struct rsbac_fs_file_t file)
  {
    return 0;
  }
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
	rwlock_init(&(rwlock->rwlock));
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
	init_waitqueue_head(&(queue->queue));
	return 0;
}

inline int xp_wait_until_condition(struct xp_queue *queue, int (*cfunction)(void *), void *cparam, int allow_interrupt)
{
	/* wait until cfunction(cparam) != 0 (condition is true) */

	if (allow_interrupt)
	{
		return wait_event_interruptible(queue->queue, cfunction(cparam) != 0);
	}
	else
	{
		wait_event(queue->queue, cfunction(cparam) != 0);
	}

	return 0;
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
	return rsbac_kmalloc(size);
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
	return 0;
}

inline int xp_verify_user_readable(const void *user_ptr, size_t size)
{
	return 0;
}


/* path attribute */

inline int xp_is_absolute_path(const char *path)
{
	return (path[0] == '/');
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

inline int xp_fill_file_struct(struct dazuko_file_struct *dfs)
{
	int	length;

	/* make sure we have access to everything */

	if (dfs == NULL)
		return -1;

	/* check if filename has already been filled in */
	if (dfs->filename != NULL)
		return 0;

	if (dfs->extra_data == NULL)
		return -1;

	if (dfs->extra_data->dentry == NULL)
		return -1;

	if (dfs->extra_data->dentry->d_inode == NULL)
		return -1;

	/* ok, we have everything we need */

	length = rsbac_get_full_path_length(dfs->extra_data->dentry);
	if (length < 1)
		return -1;

	dfs->extra_data->full_filename = xp_malloc(length + 1);
	if (dfs->extra_data->full_filename == NULL)
		return -1;

	/* the full_filename will need to be deleted later */
	dfs->extra_data->free_full_filename = 1;

	if (rsbac_get_full_path(dfs->extra_data->dentry, dfs->extra_data->full_filename, length + 1) < 1)
		return -1;

	/* find the actual value of the length */
	dfs->extra_data->full_filename_length = dazuko_strlen(dfs->extra_data->full_filename);

	/* reference copy of full path */
	dfs->filename = dfs->extra_data->full_filename;

	dfs->filename_length = dfs->extra_data->full_filename_length;

	dfs->file_p.size = dfs->extra_data->dentry->d_inode->i_size;
	dfs->file_p.set_size = 1;
	dfs->file_p.uid = dfs->extra_data->dentry->d_inode->i_uid;
	dfs->file_p.set_uid = 1;
	dfs->file_p.gid = dfs->extra_data->dentry->d_inode->i_gid;
	dfs->file_p.set_gid = 1;
	dfs->file_p.mode = dfs->extra_data->dentry->d_inode->i_mode;
	dfs->file_p.set_mode = 1;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	dfs->file_p.device_type = dfs->extra_data->dentry->d_inode->i_dev;
#else
	dfs->file_p.device_type = dfs->extra_data->dentry->d_inode->i_rdev;
#endif
	dfs->file_p.set_device_type = 1;

	return 0;
}

static int dazuko_file_struct_cleanup(struct dazuko_file_struct **dfs)
{
	if (dfs == NULL)
		return 0;

	if (*dfs == NULL)
		return 0;

	if ((*dfs)->extra_data != NULL)
	{
		if ((*dfs)->extra_data->free_full_filename)
			xp_free((*dfs)->extra_data->full_filename);

		xp_free((*dfs)->extra_data);
	}

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
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

	/* if file's are available and they match,
	 * then we say that the id's match
	 * ("file" is only used to unregister daemons and
	 * here we allow other processes to do this)
	 * Note: this is a Linux-only "hack" */
	if (id1->file != NULL && id1->file == id2->file)
		return DAZUKO_SAME;

	if (id1->pid == id2->pid && id1->current_p == id2->current_p && id1->files == id2->files)
		return DAZUKO_SAME;

	if (check_related)
	{
		if (check_parent(id1->current_p, id2->current_p) == 0)
		{
			return DAZUKO_CHILD;
		}
		else if (id1->pid == id2->pid || id1->current_p == id2->current_p || id1->files == id2->files)
		{
			return DAZUKO_SUSPICIOUS;
		}
	}

	return DAZUKO_DIFFERENT;
}

int xp_id_free(struct xp_daemon_id *id)
{
	xp_free(id);

	return 0;
}

struct xp_daemon_id* xp_id_copy(struct xp_daemon_id *id)
{
	struct xp_daemon_id	*ptr;

	if (id == NULL)
		return NULL;

	ptr = (struct xp_daemon_id *)xp_malloc(sizeof(struct xp_daemon_id));

	if (ptr != NULL)
	{
		ptr->pid = id->pid;
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
	if (rsbac_daz_get_ttl() == 0)
		return -1;

	rsbac_daz_set_ttl((rsbac_time_t)ttl);

	rsbac_daz_flush_cache();

	return 0;
}


/* include/exclude paths */

int xp_set_path(const char *path, int type)
{
	return 0;
}


/* system hook */

inline int xp_sys_hook()
{
	/* Called insmod when inserting the module. */

	/* register the dazuko device */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	dev_major = register_chrdev(CONFIG_RSBAC_DAZ_DEV_MAJOR, DEVICE_NAME, &fops);

	devfs_mk_cdev(MKDEV(dev_major, CONFIG_RSBAC_DAZ_DEV_MAJOR), S_IFCHR | S_IRUSR | S_IWUSR, DEVICE_NAME);
#else
	#ifdef CONFIG_DEVFS_FS
		dev_major = devfs_register_chrdev(CONFIG_RSBAC_DAZ_DEV_MAJOR, DEVICE_NAME, &fops);
		devfs_register(NULL, DEVICE_NAME, DEVFS_FL_DEFAULT,
			dev_major, 0, S_IFCHR | S_IRUSR | S_IWUSR,
			&fops, NULL);
	#else
		dev_major = register_chrdev(CONFIG_RSBAC_DAZ_DEV_MAJOR, DEVICE_NAME, &fops);
	#endif
#endif
	if (dev_major < 0)
	{
		xp_print("dazuko: unable to register device chrdev, err=%d\n", dev_major);
		return dev_major;
	}

	/* initialization complete */

	return 0;
}

inline int xp_sys_unhook()
{
	/* Called by rmmod when removing the module. */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	unregister_chrdev(dev_major, DEVICE_NAME);

	devfs_remove(DEVICE_NAME);
#else
	#ifdef CONFIG_DEVFS_FS
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

	p = (char *)xp_malloc(size);
	if (!p)
		return -1;

	va_start(args, fmt);
	dazuko_vsnprintf(p, size, fmt, args);
	va_end(args);

	p[size-1] = 0;

	printk(p);
	rsbac_printk(p);

	xp_free(p);

	return 0;
}


/* ioctl's */

int linux_dazuko_device_open(struct inode *inode, struct file *file)
{
	DPRINT(("dazuko: linux_dazuko_device_open() [%d]\n", current->pid));

	return 0;
}

ssize_t linux_dazuko_device_read(struct file *file, char *buffer, size_t length, loff_t *pos)
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
		return -ENODEV;

	/* print dev_major to a string
	 * and get length (with terminator) */
	dazuko_bzero(tmp, sizeof(tmp));

	dev_major_len = dazuko_snprintf(tmp, sizeof(tmp), "%d", dev_major) + 1;

	if (tmp[sizeof(tmp)-1] != 0)
	{
		xp_print("dazuko: failing device_read, device number overflow for dameon %d (dev_major=%d)\n", current->pid, dev_major);
		return -EFAULT;
	}

	if (length < dev_major_len)
		return -EINVAL;

	/* copy dev_major string to userspace */
	if (xp_copyout(tmp, buffer, dev_major_len) != 0)
		return -EFAULT;

	*pos = dev_major_len;

	return dev_major_len;
}

ssize_t linux_dazuko_device_write(struct file *file, const char *buffer, size_t length, loff_t *pos)
{
	struct xp_daemon_id	xp_id;
	char			tmpbuffer[32];
	int			size;

	size = length;
	if (length >= sizeof(tmpbuffer))
		size = sizeof(tmpbuffer) -1;

	/* copy request pointer string to kernelspace */
	if (xp_copyin(buffer, tmpbuffer, size) != 0)
		return -EFAULT;

	tmpbuffer[size] = 0;

	xp_id.pid = current->pid;
	xp_id.file = file;
	xp_id.current_p = current;
	xp_id.files = current->files;

	if (dazuko_handle_user_request(tmpbuffer, &xp_id) == 0)
		return length;
	else
		return -EINTR;
}

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
		return -EFAULT;
	}

	xp_id.pid = current->pid;
	xp_id.file = file;
	xp_id.current_p = current;
	xp_id.files = current->files;

	error = dazuko_handle_user_request_compat1((void *)param, _IOC_NR(cmd), &xp_id);

	if (error != 0)
	{
		/* general error occurred */

		return -EPERM;
	}

	return error;
}

int linux_dazuko_device_release(struct inode *inode, struct file *file)
{
	struct xp_daemon_id	xp_id;

	DPRINT(("dazuko: dazuko_device_release() [%d]\n", current->pid));

	xp_id.pid = current->pid;
	xp_id.file = file;
	xp_id.current_p = current;
	xp_id.files = current->files;

	return dazuko_unregister_daemon(&xp_id);
}


/************************************************* */
/*          Externally visible functions           */
/************************************************* */

#ifdef CONFIG_RSBAC_INIT_DELAY
int rsbac_init_daz(void)
#else
int __init rsbac_init_daz(void)
#endif
  {
    if (rsbac_is_initialized())
      {
#ifdef CONFIG_RSBAC_RMSG
        rsbac_printk(KERN_WARNING "rsbac_init_daz(): RSBAC already initialized\n");
#endif
#ifdef CONFIG_RSBAC_RMSG_NOSYSLOG
        if (!rsbac_nosyslog)
#endif
        printk(KERN_WARNING "rsbac_init_daz(): RSBAC already initialized\n");
        return(-RSBAC_EREINIT);
      }

    /* init data structures */
#ifdef CONFIG_RSBAC_RMSG
    rsbac_printk(KERN_INFO "rsbac_init_daz(): Initializing RSBAC: DAZuko subsystem\n");
#endif
#ifdef CONFIG_RSBAC_RMSG_NOSYSLOG
    if (!rsbac_nosyslog)
#endif
    printk(KERN_INFO "rsbac_init_daz(): Initializing RSBAC: DAZuko subsystem\n");

    return dazuko_init();
  }


enum rsbac_adf_req_ret_t
   rsbac_adf_request_daz (enum  rsbac_adf_request_t     request,
                                rsbac_pid_t             caller_pid,
                          enum  rsbac_target_t          target,
                          union rsbac_target_id_t       tid,
                          enum  rsbac_attribute_t       attr,
                          union rsbac_attribute_value_t attr_val,
                                rsbac_uid_t             owner)
  {
    struct dazuko_file_struct *dfs = NULL;
    struct xp_daemon_id xp_id;
    int error = 0;
    int check_error = 0;
    struct event_properties event_p;
    int event;
    int daemon_allowed;
    struct slot_list *sl = NULL;

    union rsbac_target_id_t       i_tid;
    union rsbac_attribute_value_t i_attr_val1;

    switch (request)
      {
		case R_DELETE:
			if (target == T_FILE)
			{
				event = DAZUKO_ON_UNLINK;
				daemon_allowed = 1;
			}
			else if (target == T_DIR)
			{
				event = DAZUKO_ON_RMDIR;
				daemon_allowed = 1;
			}
			else
			{
                          return DO_NOT_CARE;
			}
			break;
		case R_CLOSE:
			if (target == T_FILE)
			{
				event = DAZUKO_ON_CLOSE;
				daemon_allowed = 1;
			}
			else
			{
                          return DO_NOT_CARE;
			}
			break;

		case R_EXECUTE:
			if (target == T_FILE)
			{
				event = DAZUKO_ON_EXEC;
				daemon_allowed = 0;
			}
			else
			{
                          return DO_NOT_CARE;
			}
			break;

		case R_APPEND_OPEN:
		case R_READ_WRITE_OPEN:
		case R_READ_OPEN:
		case R_WRITE_OPEN:
			if (target == T_FILE)
			{
				event = DAZUKO_ON_OPEN;
				daemon_allowed = 1;
			}
			else
			if (target == T_DEV)
			{
			  if(   (tid.dev.type == D_char)
			     && (MAJOR(tid.dev.id) == CONFIG_RSBAC_DAZ_DEV_MAJOR)
			    )
			    {
                              i_tid.process = caller_pid;
                              if (rsbac_get_attr(DAZ,
                                                 T_PROCESS,
                                                 i_tid,
                                                 A_daz_scanner,
                                                 &i_attr_val1,
                                                 TRUE))
                                {
#ifdef CONFIG_RSBAC_RMSG
                                  rsbac_printk(KERN_WARNING
                                               "rsbac_adf_request_daz(): rsbac_get_attr() returned error!\n");
#endif
#ifdef CONFIG_RSBAC_RMSG_NOSYSLOG
                                  if (!rsbac_nosyslog)
#endif
                                    printk(KERN_WARNING
                                           "rsbac_adf_request_daz(): rsbac_get_attr() returned error!\n");
                                  return(NOT_GRANTED);
                                }
                              /* if scanner, then grant */
                              if (i_attr_val1.daz_scanner)
                                return(GRANTED);
                              else
                                return(NOT_GRANTED);
			    }
			  else
			    return DO_NOT_CARE;
			}
			else
			{
                          return DO_NOT_CARE;
			}
			break;

        case R_MODIFY_ATTRIBUTE:
            switch(attr)
              {
                case A_daz_scanned:
                case A_daz_scanner:
                case A_system_role:
                case A_daz_role:
                /* All attributes (remove target!) */
                case A_none:
                  /* Security Officer? */
                  i_tid.user = owner;
                  if (rsbac_get_attr(DAZ,
                                     T_USER,
                                     i_tid,
                                     A_daz_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
#ifdef CONFIG_RSBAC_RMSG
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_daz(): rsbac_get_attr() returned error!\n");
#endif
#ifdef CONFIG_RSBAC_RMSG_NOSYSLOG
                      if (!rsbac_nosyslog)
#endif
                      printk(KERN_WARNING
                             "rsbac_adf_request_daz(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* if sec_officer, then grant */
                  if (i_attr_val1.system_role == SR_security_officer)
                    return(GRANTED);
                  else
                    return(NOT_GRANTED);

                default:
                  return(DO_NOT_CARE);
              }

        case R_READ_ATTRIBUTE:
            switch(attr)
              {
                /* every user may see scan status of files */
                case A_daz_scanned:
                  return(GRANTED);
                /* ...but only security officers may see other attributes */
                case A_system_role:
                case A_daz_role:
                case A_daz_scanner:
                  /* Security Officer? */
                  i_tid.user = owner;
                  if (rsbac_get_attr(DAZ,
                                     T_USER,
                                     i_tid,
                                     A_daz_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
#ifdef CONFIG_RSBAC_RMSG
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_daz(): rsbac_get_attr() returned error!\n");
#endif
#ifdef CONFIG_RSBAC_RMSG_NOSYSLOG
                      if (!rsbac_nosyslog)
#endif
                      printk(KERN_WARNING
                             "rsbac_adf_request_daz(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* if sec_officer, then grant */
                  if (i_attr_val1.system_role == SR_security_officer)
                    return(GRANTED);
                  else
                    return(NOT_GRANTED);

                default:
                  return(DO_NOT_CARE);
              }

        case R_SWITCH_MODULE:
            switch(target)
              {
                case T_NONE:
                  /* we need the switch_target */
                  if(attr != A_switch_target)
                    return(UNDEFINED);
                  /* do not care for other modules */
                  if(   (attr_val.switch_target != DAZ)
                     #ifdef CONFIG_RSBAC_SOFTMODE
                     && (attr_val.switch_target != SOFTMODE)
                     #endif
                    )
                    return(DO_NOT_CARE);
                  /* test owner's daz_role */
                  i_tid.user = owner;
                  if (rsbac_get_attr(DAZ,
                                     T_USER,
                                     i_tid,
                                     A_daz_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
#ifdef CONFIG_RSBAC_RMSG
                      rsbac_printk(KERN_WARNING "rsbac_adf_request_daz(): rsbac_get_attr() returned error!\n");
#endif
#ifdef CONFIG_RSBAC_RMSG_NOSYSLOG
                      if (!rsbac_nosyslog)
#endif
                      printk(KERN_WARNING "rsbac_adf_request_daz(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* security officer? -> grant  */
                  if (i_attr_val1.system_role == SR_security_officer)
                    return(GRANTED);
                  else
                    return(NOT_GRANTED);

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }
              
/*********************/
        default: return DO_NOT_CARE;
      }

#if defined(CONFIG_RSBAC_DAZ_CACHE)
    /* get daz_scanned for file */
    if (rsbac_get_attr(DAZ,
                       T_FILE,
                       tid,
                       A_daz_scanned,
                       &i_attr_val1,
                       TRUE))
      {
#ifdef CONFIG_RSBAC_RMSG
        rsbac_printk(KERN_WARNING
                     "rsbac_adf_request_daz(): rsbac_get_attr() returned error!\n");
#endif
#ifdef CONFIG_RSBAC_RMSG_NOSYSLOG
        if (!rsbac_nosyslog)
#endif
          printk(KERN_WARNING
                 "rsbac_adf_request_daz(): rsbac_get_attr() returned error!\n");
        return(-RSBAC_EREADFAILED);
      }
    if(i_attr_val1.daz_scanned == DAZ_clean)
      return GRANTED;
#endif

	xp_id.pid = current->pid;
	xp_id.file = NULL;
	xp_id.current_p = current;
	xp_id.files = current->files;

	check_error = dazuko_check_access(event, daemon_allowed, &xp_id, &sl);

	if (!check_error)
	{
		dazuko_bzero(&event_p, sizeof(event_p));
/*
		event_p.flags = flags;
		event_p.set_flags = 1;
		event_p.mode = mode;
		event_p.set_mode = 1;
*/
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

				dfs->extra_data->dentry = tid.file.dentry_p;

				error = dazuko_process_access(event, dfs, &event_p, sl);

#if defined(CONFIG_RSBAC_DAZ_CACHE)
                                if(!error)
                                  i_attr_val1.daz_scanned = DAZ_clean;
                                else
                                  i_attr_val1.daz_scanned = DAZ_infected;

                                if (rsbac_set_attr(DAZ,
                                    target,
                                    tid,
                                    A_daz_scanned,
                                    i_attr_val1))
                                  {
#ifdef CONFIG_RSBAC_RMSG
                                    rsbac_printk(KERN_WARNING "rsbac_adf_request_daz(): rsbac_set_attr() returned error!\n");
#endif
#ifdef CONFIG_RSBAC_RMSG_NOSYSLOG
                                    if (!rsbac_nosyslog)
#endif
                                    printk(KERN_WARNING "rsbac_adf_request_daz(): rsbac_set_attr() returned error!\n");
                                    return NOT_GRANTED;
                                  }
#endif
			}
			else
			{
				xp_free(dfs);
				dfs = NULL;
			}

			dazuko_file_struct_cleanup(&dfs);
		}
	}

        if(!error)
          return GRANTED;
        else
          return NOT_GRANTED;
  }; /* end of rsbac_adf_request_daz() */


/*****************************************************************************/
/* If the request returned granted and the operation is performed,           */
/* the following function can be called by the AEF to get all aci set        */
/* correctly. For write accesses that are performed fully within the kernel, */
/* this is usually not done to prevent extra calls, including R_CLOSE for    */
/* cleaning up. Because of this, the write boundary is not adjusted - there  */
/* is no user-level writing anyway...                                        */
/* The second instance of target specification is the new target, if one has */
/* been created, otherwise its values are ignored.                           */
/* On success, 0 is returned, and an error from rsbac/error.h otherwise.     */

int  rsbac_adf_set_attr_daz(
                      enum  rsbac_adf_request_t     request,
                            rsbac_pid_t             caller_pid,
                      enum  rsbac_target_t          target,
                      union rsbac_target_id_t       tid,
                      enum  rsbac_target_t          new_target,
                      union rsbac_target_id_t       new_tid,
                      enum  rsbac_attribute_t       attr,
                      union rsbac_attribute_value_t attr_val,
                            rsbac_uid_t             owner)
  {
    struct dazuko_file_struct *dfs = NULL;
    struct xp_daemon_id xp_id;
    int check_error = 0;
    struct event_properties event_p;
    int event;
    int daemon_allowed;
    union rsbac_target_id_t       i_tid;
    union rsbac_attribute_value_t i_attr_val1;
    union rsbac_attribute_value_t i_attr_val2;
    struct slot_list *sl = NULL;

    switch (request)
      {
		case R_DELETE:
			if (target == T_FILE)
			{
			        reset_scanned(tid.file);
				event = DAZUKO_ON_UNLINK;
				daemon_allowed = 1;
			}
			else if (target == T_DIR)
			{
				event = DAZUKO_ON_RMDIR;
				daemon_allowed = 1;
			}
			else
			{
                          return(0);
			}
			break;
		case R_CLOSE:
			if (target == T_FILE)
			{
				event = DAZUKO_ON_CLOSE;
				daemon_allowed = 1;
			}
			else
			{
                          return(0);
			}
			break;

		case R_EXECUTE:
			if (target == T_FILE)
			{
                  /* get daz_scanner for file */
                  if (rsbac_get_attr(DAZ,
                                     T_FILE,
                                     tid,
                                     A_daz_scanner,
                                     &i_attr_val1,
                                     TRUE))
                    {
#ifdef CONFIG_RSBAC_RMSG
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_set_attr_daz(): rsbac_get_attr() returned error!\n");
#endif
#ifdef CONFIG_RSBAC_RMSG_NOSYSLOG
                      if (!rsbac_nosyslog)
#endif
                      printk(KERN_WARNING
                             "rsbac_adf_set_attr_daz(): rsbac_get_attr() returned error!\n");
                      return(-RSBAC_EREADFAILED);
                    }
                  /* get for process */
                  i_tid.process = caller_pid;
                  if (rsbac_get_attr(DAZ,
                                     T_PROCESS,
                                     i_tid,
                                     A_daz_scanner,
                                     &i_attr_val2,
                                     FALSE))
                    {
#ifdef CONFIG_RSBAC_RMSG
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_set_attr_daz(): rsbac_get_attr() returned error!\n");
#endif
#ifdef CONFIG_RSBAC_RMSG_NOSYSLOG
                      if (!rsbac_nosyslog)
#endif
                      printk(KERN_WARNING
                             "rsbac_adf_set_attr_daz(): rsbac_get_attr() returned error!\n");
                      return(-RSBAC_EREADFAILED);
                    }
                  /* and set for process, if different */
                  if(i_attr_val1.daz_scanner != i_attr_val2.daz_scanner)
                    if (rsbac_set_attr(DAZ,
                                       T_PROCESS,
                                       i_tid,
                                       A_daz_scanner,
                                       i_attr_val1))
                      {
#ifdef CONFIG_RSBAC_RMSG
                        rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_daz(): rsbac_set_attr() returned error!\n");
#endif
#ifdef CONFIG_RSBAC_RMSG_NOSYSLOG
                        if (!rsbac_nosyslog)
#endif
                        printk(KERN_WARNING "rsbac_adf_set_attr_daz(): rsbac_set_attr() returned error!\n");
                        return(-RSBAC_EWRITEFAILED);
                      }
				event = DAZUKO_ON_EXEC;
				daemon_allowed = 0;
			}
			else
			{
                          return(0);
			}
			break;

		case R_APPEND_OPEN:
		case R_READ_WRITE_OPEN:
		case R_WRITE_OPEN:
			if (target == T_FILE)
			{
			        reset_scanned(tid.file);
				event = DAZUKO_ON_OPEN;
				daemon_allowed = 1;
			}
			else
			{
                          return(0);
			}
			break;

		case R_READ_OPEN:
			if (target == T_FILE)
			{
				event = DAZUKO_ON_OPEN;
				daemon_allowed = 1;
			}
			else
			{
                          return(0);
			}
			break;

        case R_CLONE:
            if (target == T_PROCESS)
              {
                /* Get daz_scanner from first process */
                if (rsbac_get_attr(DAZ,
                                   T_PROCESS,
                                   tid,
                                   A_daz_scanner,
                                   &i_attr_val1,
                                   FALSE))
                  {
#ifdef CONFIG_RSBAC_RMSG
                    rsbac_printk(KERN_WARNING
                           "rsbac_adf_set_attr_daz(): rsbac_get_attr() returned error!\n");
#endif
#ifdef CONFIG_RSBAC_RMSG_NOSYSLOG
                    if (!rsbac_nosyslog)
#endif
                    printk(KERN_WARNING
                           "rsbac_adf_set_attr_daz(): rsbac_get_attr() returned error!\n");
                    return(-RSBAC_EREADFAILED);
                  }
                /* Set daz_scanner for new process, if set for first */
                if (   i_attr_val1.daz_scanner
                    && (rsbac_set_attr(DAZ,
                                       T_PROCESS,
                                       new_tid,
                                       A_daz_scanner,
                                       i_attr_val1)) )
                  {
#ifdef CONFIG_RSBAC_RMSG
                    rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_daz(): rsbac_set_attr() returned error!\n");
#endif
#ifdef CONFIG_RSBAC_RMSG_NOSYSLOG
                    if (!rsbac_nosyslog)
#endif
                    printk(KERN_WARNING "rsbac_adf_set_attr_daz(): rsbac_set_attr() returned error!\n");
                    return(-RSBAC_EWRITEFAILED);
                  }
                return(0);
              }
            else
              return(0);

/*********************/
        default: return(0);
      }

#if defined(CONFIG_RSBAC_DAZ_CACHE)
    /* get daz_scanned for file */
    if (rsbac_get_attr(DAZ,
                       T_FILE,
                       tid,
                       A_daz_scanned,
                       &i_attr_val1,
                       TRUE))
      {
#ifdef CONFIG_RSBAC_RMSG
        rsbac_printk(KERN_WARNING
                     "rsbac_adf_set_attr_daz(): rsbac_get_attr() returned error!\n");
#endif
#ifdef CONFIG_RSBAC_RMSG_NOSYSLOG
        if (!rsbac_nosyslog)
#endif
          printk(KERN_WARNING
                 "rsbac_adf_set_attr_daz(): rsbac_get_attr() returned error!\n");
        return(-RSBAC_EREADFAILED);
      }
    if(i_attr_val1.daz_scanned == DAZ_clean)
      return 0;
#endif

	xp_id.pid = current->pid;
	xp_id.file = NULL;
	xp_id.current_p = current;
	xp_id.files = current->files;

	check_error = dazuko_check_access(event, daemon_allowed, &xp_id, &sl);

	if (!check_error)
	{
		dazuko_bzero(&event_p, sizeof(event_p));
/*
		event_p.flags = flags;
		event_p.set_flags = 1;
		event_p.mode = mode;
		event_p.set_mode = 1;
*/
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

				dfs->extra_data->dentry = tid.file.dentry_p;

				dazuko_process_access(event, dfs, &event_p, sl);
			}
			else
			{
				xp_free(dfs);
				dfs = NULL;
			}

			dazuko_file_struct_cleanup(&dfs);
		}
	}

    return(0);
  }; /* end of rsbac_adf_set_attr_daz() */

/* end of rsbac/adf/daz/daz_main.c */

