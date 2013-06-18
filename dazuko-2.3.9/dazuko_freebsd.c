/* Dazuko FreeBSD. Allow FreeBSD file access control for 3rd-party applications.
   Written by John Ogness <dazukocode@ogness.net>

   Copyright (c) 2003, 2004, 2005 H+BEDV Datentechnik GmbH
   Copyright (c) 2006 Avira GmbH
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:

   1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

   3. Neither the name of Dazuko nor the names of its contributors may be used
   to endorse or promote products derived from this software without specific
   prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.
*/


#include <sys/types.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/proc.h>
#include <sys/ioccom.h>
#include <sys/malloc.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/syscall.h>
#include <sys/filio.h>
#include <sys/file.h>
#include <machine/stdarg.h>

#include <sys/namei.h>
#include <sys/param.h>
#include <sys/vnode.h>

#include "dazuko_freebsd.h"
#include "dazuko_core.h"


#ifndef DAZUKO_DM
#define DAZUKO_DM 33
#endif


d_read_t freebsd_dazuko_device_read;
d_write_t freebsd_dazuko_device_write;
d_open_t freebsd_dazuko_device_open;
d_close_t freebsd_dazuko_device_close;

extern struct xp_atomic active;

static int	syscall_in_use = 0;
static int	dev_major = DAZUKO_DM;
static dev_t	sdev = NULL;

#if defined(ON_OPEN_SUPPORT)
static int freebsd_dazuko_sys_open(struct proc *p, struct open_args *uap);
static struct sysent freebsd_dazuko_sys_open_sysent = { (sizeof(struct open_args) / sizeof(register_t)), (sy_call_t*)freebsd_dazuko_sys_open };
static sy_call_t *original_sys_open = NULL;

static int freebsd_dazuko_sys_dup(struct proc *p, struct dup_args *uap);
static struct sysent freebsd_dazuko_sys_dup_sysent = { (sizeof(struct dup_args) / sizeof(register_t)), (sy_call_t*)freebsd_dazuko_sys_dup };
static sy_call_t *original_sys_dup = NULL;
#endif

#if defined(ON_OPEN_SUPPORT) || defined(ON_CLOSE_SUPPORT) || defined(ON_CLOSE_MODIFIED_SUPPORT)
static int freebsd_dazuko_sys_dup2(struct proc *p, struct dup2_args *uap);
static struct sysent freebsd_dazuko_sys_dup2_sysent = { (sizeof(struct dup2_args) / sizeof(register_t)), (sy_call_t*)freebsd_dazuko_sys_dup2 };
static sy_call_t *original_sys_dup2 = NULL;
#endif

#if defined(ON_CLOSE_SUPPORT) || defined(ON_CLOSE_MODIFIED_SUPPORT)
static int freebsd_dazuko_sys_close(struct proc *p, struct close_args *uap);
static struct sysent freebsd_dazuko_sys_close_sysent = { 1, (sy_call_t*)freebsd_dazuko_sys_close };
static sy_call_t *original_sys_close = NULL;
#endif

#ifdef ON_EXEC_SUPPORT
static int freebsd_dazuko_sys_execve(struct proc *p, struct execve_args *uap);
static struct sysent freebsd_dazuko_sys_execve_sysent = { 3, (sy_call_t*)freebsd_dazuko_sys_execve };
static sy_call_t *original_sys_execve = NULL;
#endif

#ifdef ON_UNLINK_SUPPORT
static int freebsd_dazuko_sys_unlink(struct proc *p, struct unlink_args *uap);
static struct sysent freebsd_dazuko_sys_unlink_sysent = { 1, (sy_call_t*)freebsd_dazuko_sys_unlink };
static sy_call_t *original_sys_unlink = NULL;
#endif

#ifdef ON_RMDIR_SUPPORT
static int freebsd_dazuko_sys_rmdir(struct proc *p, struct rmdir_args *uap);
static struct sysent freebsd_dazuko_sys_rmdir_sysent = { 1, (sy_call_t*)freebsd_dazuko_sys_rmdir };
static sy_call_t *original_sys_rmdir = NULL;
#endif

static struct vnode	*orig_rootmnt = NULL;

static struct cdevsw	cdepts = {
					freebsd_dazuko_device_open,
					freebsd_dazuko_device_close,
					freebsd_dazuko_device_read,
					freebsd_dazuko_device_write,
					noioctl,
					nopoll,
					nommap,
					nostrategy,
					DEVICE_NAME,
					DAZUKO_DM,
					nodump,
					nopsize,
					D_TTY,
					-1
				};


MALLOC_DECLARE(M_DAZUKOBUF);
MALLOC_DEFINE(M_DAZUKOBUF, "dazukobuffer", "buffer for dazuko module");


static inline void freebsd_setupid(struct xp_daemon_id *xp_id, struct proc *p)
{
	if (xp_id == NULL || p == NULL)
	{
		xp_print("dazuko: warning: freebsd_setupid() received NULL\n");
		return;
	}

	if (p->p_fd == NULL)
	{
		xp_print("dazuko: warning: freebsd_setupid().p_fd == NULL\n");
		return;
	}

	xp_id->proc = p;
	xp_id->pid = p->p_pid;
	xp_id->fd = p->p_fd;
}


/* mutex */

inline void xp_init_mutex(struct xp_mutex *mutex)
{
	simple_lock_init(&(mutex->lock));
}

inline void xp_down(struct xp_mutex *mutex)
{
	simple_lock(&(mutex->lock));
}

inline void xp_up(struct xp_mutex *mutex)
{
	simple_unlock(&(mutex->lock));
}

inline void xp_destroy_mutex(struct xp_mutex *mutex)
{
}


/* read-write lock */

inline void xp_init_rwlock(struct xp_rwlock *rwlock)
{
	lockinit(&(rwlock->lock), PVM, DEVICE_NAME, 0, 0);
}

inline void xp_write_lock(struct xp_rwlock *rwlock)
{
	lockmgr(&(rwlock->lock), LK_EXCLUSIVE, 0, curproc);
}

inline void xp_write_unlock(struct xp_rwlock *rwlock)
{
	lockmgr(&(rwlock->lock), LK_RELEASE, 0, curproc);
}

inline void xp_read_lock(struct xp_rwlock *rlock)
{
	lockmgr(&(rlock->lock), LK_SHARED, 0, curproc);
}

inline void xp_read_unlock(struct xp_rwlock *rlock)
{
	lockmgr(&(rlock->lock), LK_RELEASE, 0, curproc);
}

inline void xp_destroy_rwlock(struct xp_rwlock *rwlock)
{
}


/* wait-notify queue */

inline int xp_init_queue(struct xp_queue *queue)
{
	return 0;
}

inline int xp_wait_until_condition(struct xp_queue *queue, int (*cfunction)(void *), void *cparam, int allow_interrupt)
{
	int	rc = 0;
	int	prio = PVM;

	if (allow_interrupt)
		prio |= PCATCH;

	for (;;)
	{
		if (asleep(queue, prio, DEVICE_NAME, 0) != 0)
		{
			rc = -1;
			break;
		}

		if (cfunction(cparam))
			break;

		if (await(prio, 0) != 0)
		{
			rc = -1;
			break;
		}
	}

	asleep(NULL, 0, "", 0);

	return rc;
}

inline int xp_notify(struct xp_queue *queue)
{
	wakeup(queue);

	return 0;
}

inline int xp_destroy_queue(struct xp_queue *queue)
{
	return 0;
}


/* memory */

inline void* xp_malloc(size_t size)
{
	return malloc(size, M_DAZUKOBUF, M_WAITOK);
}

inline int xp_free(void *ptr)
{
	free(ptr, M_DAZUKOBUF);

	return 0;
}

inline int xp_copyin(const void *user_src, void *kernel_dest, size_t size)
{
	return copyin(user_src, kernel_dest, size);
}

inline int xp_copyout(const void *kernel_src, void *user_dest, size_t size)
{
	return copyout(kernel_src, user_dest, size);
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
	atomic->value = value;

	return 0;
}

inline int xp_atomic_inc(struct xp_atomic *atomic)
{
	(atomic->value)++;

	return 0;
}

inline int xp_atomic_dec(struct xp_atomic *atomic)
{
	(atomic->value)--;

	return 0;
}

inline int xp_atomic_read(struct xp_atomic *atomic)
{
	return atomic->value;
}


/* file structure */

static void freebsd_get_filename_full_fileinfo(struct proc *p, const char *path, char **fullpath, char **freefullpath, struct file_properties *file_p, int follow_symlinks)
{
	struct proc		localp;
	struct nameidata	nd;
	struct filedesc		localfd;
	struct vattr		vattr;
	int			error = 0;

	if (p == NULL || path == NULL || fullpath == NULL || freefullpath == NULL || file_p == NULL)
		return;

	dazuko_bzero(&nd, sizeof(nd));
	dazuko_bzero(&localp, sizeof(localp));
	dazuko_bzero(&localfd, sizeof(localfd));
	dazuko_bzero(file_p, sizeof(struct file_properties));

	NDINIT(&nd, LOOKUP, follow_symlinks ? FOLLOW : NOFOLLOW, UIO_USERSPACE, path, p);

	error = namei(&nd);

	if (error != 0)
	{
		if (error == ENOENT)
		{
			/* let's try to resolve the parent dir (if possible) */
			char * kpath = xp_malloc(MAXPATHLEN+1);
			char * fname = kpath;
			char * lookuppath = ".";
			char * pfullpath = NULL;
			char * pfreefullpath = NULL;
			size_t len;
			int i;
			struct nameidata ndparent;

			if (kpath == NULL)
				return;

			dazuko_bzero(kpath, MAXPATHLEN+1);
			copyinstr(path, kpath, MAXPATHLEN+1, &len);

			/* find the last "/" */
			for (i=strlen(kpath) ; i>=0 ; i--)
			{
				if (kpath[i] == '/')
				{
					if (i == 0)
					{
						/* the only "/" is the root */
						lookuppath = "/";
					}
					else
					{
						kpath[i] = 0;
						lookuppath = kpath;
					}

					fname = kpath + i + 1;

					break;
				}
			}

			/* at this point we have:
			 * lookuppath = the name of the parent directory to lookup
			 * fname = the file name that was not found by the previous namei
			 */

			dazuko_bzero(&ndparent, sizeof(ndparent));

			NDINIT(&ndparent, LOOKUP, follow_symlinks ? FOLLOW : NOFOLLOW, UIO_SYSSPACE, lookuppath, p);

			error = namei(&ndparent);

			if (error)
			{
				xp_free(kpath);
				return;
			}

			if (ndparent.ni_vp != NULL)
			{
				localp.p_textvp = ndparent.ni_vp;
				localp.p_fd = &localfd;

				if (orig_rootmnt != NULL)
					localfd.fd_rdir = orig_rootmnt;
				else
					localfd.fd_rdir = ndparent.ni_rootdir;

				textvp_fullpath(&localp, &pfullpath, &pfreefullpath);

				if (pfreefullpath != NULL)
				{
					len = strlen(pfullpath) + strlen(fname) + 2;
					*fullpath = malloc(len, M_TEMP, M_WAITOK);
					if (*fullpath != NULL)
					{
						strcpy(*fullpath, pfullpath);

						/* we don't add "/" if it is root */
						if ((pfullpath[0] != '/') || (pfullpath[1] != 0))
							strcat(*fullpath, "/");

						strcat(*fullpath, fname);

						*freefullpath = *fullpath;
					}
					free(pfreefullpath, M_TEMP);
				}
			}

			NDFREE(&ndparent, 0);
			xp_free(kpath);
		}
		else
		{
			/*
			 * we need to understand why this fails sometimes
			 */
		}
	}
	else
	{
		localp.p_textvp = nd.ni_vp;
		localp.p_fd = &localfd;

		if (orig_rootmnt != NULL)
			localfd.fd_rdir = orig_rootmnt;
		else
			localfd.fd_rdir = nd.ni_rootdir;

		textvp_fullpath(&localp, fullpath, freefullpath);

		if (nd.ni_vp != NULL)
		{
			if (VOP_GETATTR(nd.ni_vp, &vattr, p->p_ucred, p) == 0)
			{
				file_p->size = vattr.va_size;
				file_p->set_size = 1;
				file_p->uid = vattr.va_uid;
				file_p->set_uid = 1;
				file_p->gid = vattr.va_gid;
				file_p->set_gid = 1;
				file_p->mode = vattr.va_mode;
				file_p->set_mode = 1;
				file_p->device_type = vattr.va_fsid;
				file_p->set_device_type = 1;

				switch (nd.ni_vp->v_type)
				{
					case VDIR:
						file_p->type = DAZUKO_DIRECTORY;
						file_p->set_type = 1;
						break;
					case VREG:
						file_p->type = DAZUKO_REGULAR;
						file_p->set_type = 1;
						break;
					case VLNK:
						file_p->type = DAZUKO_LINK;
						file_p->set_type = 1;
						break;
					default:
						break;
				}
			}
		}

		/* deref looked up vnode */
		NDFREE(&nd, 0);
	}
}

static void freebsd_get_fd_full_fileinfo(struct proc *p, int fd, char **fullpath, char **freefullpath, struct file_properties *file_p)
{
	struct proc		localp;
	struct filedesc		localfd;
	struct vattr		vattr;
	struct file		*fp;
	struct vnode		*vp;

	if (p == NULL || fullpath == NULL || freefullpath == NULL || file_p == NULL || orig_rootmnt == NULL)
		return;

	if (p->p_fd == NULL)
		return;

	if (getvnode(p->p_fd, fd, &fp) != 0)
		return;

	if (fp == NULL)
		return;

	vp = (struct vnode *)fp->f_data;

	if (vp == NULL)
		return;

	dazuko_bzero(&localp, sizeof(localp));
	dazuko_bzero(&localfd, sizeof(localfd));
	dazuko_bzero(file_p, sizeof(struct file_properties));

	localp.p_textvp = vp;
	localp.p_fd = &localfd;

	localfd.fd_rdir = orig_rootmnt;

	textvp_fullpath(&localp, fullpath, freefullpath);

	if (VOP_GETATTR(vp, &vattr, p->p_ucred, p) == 0)
	{
		file_p->size = vattr.va_size;
		file_p->set_size = 1;
		file_p->uid = vattr.va_uid;
		file_p->set_uid = 1;
		file_p->gid = vattr.va_gid;
		file_p->set_gid = 1;
		file_p->mode = vattr.va_mode;
		file_p->set_mode = 1;
		file_p->device_type = vattr.va_fsid;
		file_p->set_device_type = 1;

		switch (vp->v_type)
		{
			case VDIR:
				file_p->type = DAZUKO_DIRECTORY;
				file_p->set_type = 1;
				break;
			case VREG:
				file_p->type = DAZUKO_REGULAR;
				file_p->set_type = 1;
				break;
			case VLNK:
				file_p->type = DAZUKO_LINK;
				file_p->set_type = 1;
				break;
			default:
				break;
		}
	}
}

inline int xp_fill_file_struct(struct dazuko_file_struct *dfs)
{
	char				*fullpath = NULL;
	char				*freefullpath = NULL;
	int				length;
	struct dazuko_file_listnode	*listnode;
	int				follow_symlinks = 0;
	int				error = 0;
	int				loopcount = 0;

	if (dfs == NULL)
		return -1;

	/* check if filenames have already been filled in */
	if (dfs->aliases != NULL)
		return 0;

	if (dfs->extra_data == NULL)
		return -1;

	while (1)
	{
		loopcount++;

		listnode = (struct dazuko_file_listnode *)xp_malloc(sizeof(struct dazuko_file_listnode));
		if (listnode == NULL)
		{
			error = -1;
			break;
		}

		dazuko_bzero(listnode, sizeof(struct dazuko_file_listnode));

		if (dfs->extra_data->user_filename != NULL)
		{
			freebsd_get_filename_full_fileinfo(dfs->extra_data->p, dfs->extra_data->user_filename, &fullpath, &freefullpath, &(dfs->file_p), follow_symlinks);
		}
		else
		{
			freebsd_get_fd_full_fileinfo(dfs->extra_data->p, dfs->extra_data->fd, &fullpath, &freefullpath, &(dfs->file_p));

			/* make sure we don't loop a 2nd time */
			loopcount++;
		}

		if (freefullpath)
		{
			length = dazuko_strlen(fullpath);

			listnode->filename = (char *)xp_malloc(length + 1);
			if (listnode->filename != NULL)
			{
				memcpy(listnode->filename, fullpath, length);
				listnode->filename[length] = 0;
				listnode->filename_length = length;  /* the string length */
			}

			/* this memory is freed from a different pool than
			 * xp_malloc would use */

			free(freefullpath, M_TEMP);
		}

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

		if (!follow_symlinks && dfs->file_p.set_type && dfs->file_p.type == DAZUKO_LINK && loopcount < 2)
		{
			/* this is a link, we will grab the real path now */

			follow_symlinks = 1;
		}
		else
		{
			/* we've grabbed the real path (or we already have 2 paths), so we are done */

			break;
		}
	}

	if (!error && dfs->aliases->filename == NULL && dfs->extra_data->user_filename != NULL)
	{
		/* we couldn't get any filename, so we'll just grab the user parameter
		 * note: dfs->aliases was already allocated previously, we just have to fill it */

		for (length=0 ; fubyte((dfs->extra_data->user_filename)+length) ; length++);

		length++;

		dfs->aliases->filename = (char *)xp_malloc(length);
		if (dfs->aliases->filename != NULL)
		{
			if (xp_copyin(dfs->extra_data->user_filename, dfs->aliases->filename, length) != 0)
			{
				xp_print("dazuko: error: xp_fill_file_struct.xp_copyin() failed\n");
				xp_free(dfs->aliases->filename);
				dfs->aliases->filename = NULL;
				dfs->aliases->filename_length = 0;
			}
			else
			{
				dfs->aliases->filename_length = length - 1;  /* the string length */
			}
		}
	}

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

static inline int check_parent(struct proc *parent, struct proc *child)
{
	struct proc	*ts = child;

	if (parent == NULL || child == NULL)
		return -1;

	while (1)
	{
		if (ts == parent)
			return 0;

		if (ts->p_pptr == NULL)
			break;

		if (ts == ts->p_pptr)
			break;

		ts = ts->p_pptr;
	}

	return -1;
}

inline int xp_id_compare(struct xp_daemon_id *id1, struct xp_daemon_id *id2, int check_related)
{
	if (id1 == NULL || id2 == NULL)
		return DAZUKO_DIFFERENT;

	if (id1->pid == id2->pid && id1->proc == id2->proc && id1->fd == id2->fd)
		return DAZUKO_SAME;

	if (check_related)
	{
		if (check_parent(id1->proc, id2->proc) == 0)
		{
			return DAZUKO_CHILD;
		}
		else if (id1->pid == id2->pid || id1->proc == id2->proc || id1->fd == id2->fd)
		{
			return DAZUKO_SUSPICIOUS;
		}
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
		ptr->proc = id->proc;
		ptr->fd = id->fd;
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

static inline int check_fd(struct proc *p, int fd)
{
	if (p == NULL)
	{
		return -1;
	}
	else if (p->p_fd == NULL)
	{
		return -1;
	}
	else if (fd < 0)
	{
		return -1;
	}
	else if (fd >= p->p_fd->fd_nfiles)
	{
		return -1;
	}
	else if (p->p_fd->fd_ofiles == NULL)
	{
		return -1;
	}
	else if (p->p_fd->fd_ofiles[fd] == NULL)
	{
		return -1;
	}

	return 0;
}

#define DAZUKO_SYSCALL_WRAPPER(syscall_func) static int freebsd_dazuko_sys_##syscall_func(struct proc *p, struct syscall_func##_args *uap) \
{ \
	int	ret; \
	syscall_in_use++; \
	ret = freebsd_dazuko_sys_##syscall_func##_inner(p, uap); \
	syscall_in_use--; \
	return ret; \
}

#if defined(ON_OPEN_SUPPORT)
static inline int freebsd_dazuko_sys_open_inner(struct proc *p, struct open_args *uap)
{
	struct dazuko_file_struct	*dfs = NULL;
	struct event_properties		event_p;
	struct xp_daemon_id		xp_id;
	int				error = 0;
	int				check_error = 0;

	if (p == NULL)
	{
		xp_print("dazuko: warning: freebsd_dazuko_sys_open(NULL, ...)\n");
		check_error = -1;
	}
	else
	{
		freebsd_setupid(&xp_id, p);
		check_error = dazuko_check_access(DAZUKO_ON_OPEN, 1, &xp_id, NULL);
	}

	if (!check_error)
	{
		dazuko_bzero(&event_p, sizeof(event_p));

		if (uap == NULL)
		{
			xp_print("dazuko: warning: freebsd_dazuko_sys_open(p, NULL)\n");
			check_error = -1;
		}
		else if (p->p_cred == NULL)
		{
			xp_print("dazuko: warning: freebsd_dazuko_sys_open.p->p_cred=NULL\n");
			check_error = -1;
		}
		else
		{
			event_p.flags = uap->flags;
			event_p.set_flags = 1;
			event_p.mode = uap->mode;
			event_p.set_mode = 1;
			event_p.pid = p->p_pid;
			event_p.set_pid = 1;
			event_p.uid = p->p_cred->p_ruid;
			event_p.set_uid = 1;

			dfs = (struct dazuko_file_struct *)xp_malloc(sizeof(struct dazuko_file_struct));
			if (dfs != NULL)
			{
				dazuko_bzero(dfs, sizeof(struct dazuko_file_struct));

				dfs->extra_data = (struct xp_file_struct *)xp_malloc(sizeof(struct xp_file_struct));
				if (dfs->extra_data != NULL)
				{
					dazuko_bzero(dfs->extra_data, sizeof(struct xp_file_struct));

					dfs->extra_data->user_filename = uap->path;
					dfs->extra_data->p = p;

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
	}

	if (error)
	{
		/* access should be blocked */

		error = EPERM;
	}
	else
	{
		/* call the standard open function */
		error = original_sys_open(p, uap);
	}

	return error;
}

DAZUKO_SYSCALL_WRAPPER(open)

static inline int freebsd_dazuko_sys_dup_inner(struct proc *p, struct dup_args *uap)
{
	struct dazuko_file_struct	*dfs = NULL;
	int				error = 0;
	int				check_error = 0;
	struct event_properties		event_p;
	struct xp_daemon_id		xp_id;

	if (p == NULL)
	{
		xp_print("dazuko: warning: freebsd_dazuko_sys_dup(NULL, ...)\n");
		check_error = -1;
	}
	else
	{
		freebsd_setupid(&xp_id, p);
		check_error = dazuko_check_access(DAZUKO_ON_OPEN, 1, &xp_id, NULL);
	}

	if (!check_error)
	{
		if (uap == NULL)
		{
			check_error = -1;
		}
		else if (p->p_cred == NULL)
		{
			check_error = -1;
		}
		else if (check_fd(p, uap->fd) != 0)
		{
			check_error = -1;
		}
		else
		{
			dazuko_bzero(&event_p, sizeof(event_p));

			event_p.pid = p->p_pid;
			event_p.set_pid = 1;
			event_p.uid = p->p_cred->p_ruid;
			event_p.set_uid = 1;

			dfs = (struct dazuko_file_struct *)xp_malloc(sizeof(struct dazuko_file_struct));
			if (dfs != NULL)
			{
				dazuko_bzero(dfs, sizeof(struct dazuko_file_struct));

				dfs->extra_data = (struct xp_file_struct *)xp_malloc(sizeof(struct xp_file_struct));
				if (dfs->extra_data != NULL)
				{
					dazuko_bzero(dfs->extra_data, sizeof(struct xp_file_struct));

					dfs->extra_data->fd = uap->fd;
					dfs->extra_data->p = p;

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
	}

	if (error)
	{
		/* access should be blocked */

		error = EPERM;
	}
	else
	{
		/* call the standard dup function */
		error = original_sys_dup(p, uap);
	}

	return error;
}

DAZUKO_SYSCALL_WRAPPER(dup)
#endif

#if defined(ON_OPEN_SUPPORT) || defined(ON_CLOSE_SUPPORT) || defined(ON_CLOSE_MODIFIED_SUPPORT)
static inline int freebsd_dazuko_sys_dup2_inner(struct proc *p, struct dup2_args *uap)
{
	struct dazuko_file_struct	*dfs = NULL;
	struct event_properties		open_event_p;
	struct xp_daemon_id		xp_id;
	int				error = 0;
	int				open_check_error = 0;
#if defined(ON_CLOSE_SUPPORT) || defined(ON_CLOSE_MODIFIED_SUPPORT)
	struct event_properties		close_event_p;
	int				close_check_error = 0;
	int				will_close_newfd = 0;
#endif

	if (p == NULL)
	{
		xp_print("dazuko: warning: freebsd_dazuko_sys_dup2(NULL, ...)\n");
		open_check_error = -1;
	}
	else
	{
		freebsd_setupid(&xp_id, p);
		open_check_error = dazuko_check_access(DAZUKO_ON_OPEN, 1, &xp_id, NULL);
	}

	if (!open_check_error)
	{
		dazuko_bzero(&open_event_p, sizeof(open_event_p));

		if (uap == NULL)
		{
			open_check_error = -1;
		}
		else if (uap->from == uap->to)
		{
			/* oldfd and newfd are equal, there is nothing to do */
			open_check_error = -1;
		}
		else if (p->p_cred == NULL)
		{
			open_check_error = -1;
		}
		else if (check_fd(p, uap->from) != 0)
		{
			open_check_error = -1;
		}
		else
		{
			open_event_p.pid = p->p_pid;
			open_event_p.set_pid = 1;
			open_event_p.uid = p->p_cred->p_ruid;
			open_event_p.set_uid = 1;

			dfs = (struct dazuko_file_struct *)xp_malloc(sizeof(struct dazuko_file_struct));
			if (dfs != NULL)
			{
				dazuko_bzero(dfs, sizeof(struct dazuko_file_struct));

				dfs->extra_data = (struct xp_file_struct *)xp_malloc(sizeof(struct xp_file_struct));
				if (dfs->extra_data != NULL)
				{
					dazuko_bzero(dfs->extra_data, sizeof(struct xp_file_struct));

					dfs->extra_data->fd = uap->from;
					dfs->extra_data->p = p;

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
	}

	if (error)
	{
		/* access should be blocked */

		error = EPERM;
	}
	else
	{
		#if defined(ON_CLOSE_SUPPORT) || defined(ON_CLOSE_MODIFIED_SUPPORT)
		{
			close_check_error = dazuko_check_access(DAZUKO_ON_CLOSE, 1, &xp_id, NULL);

			if (!close_check_error)
			{

				if (check_fd(p, uap->to) == 0)
				{
					will_close_newfd = 1;
				}
			}
		}
		#endif

		/* call the standard dup2 function */
		error = original_sys_dup2(p, uap);

		#if defined(ON_CLOSE_SUPPORT) || defined(ON_CLOSE_MODIFIED_SUPPORT)
		{
			if (!close_check_error)
			{
				if (!error && will_close_newfd && check_fd(p, p->p_retval[0]) == 0)
				{
					dazuko_bzero(&close_event_p, sizeof(close_event_p));

					close_event_p.pid = p->p_pid;
					close_event_p.set_pid = 1;
					close_event_p.uid = p->p_cred->p_ruid;
					close_event_p.set_uid = 1;

					dfs = (struct dazuko_file_struct *)xp_malloc(sizeof(struct dazuko_file_struct));
					if (dfs != NULL)
					{
						dazuko_bzero(dfs, sizeof(struct dazuko_file_struct));

						dfs->extra_data = (struct xp_file_struct *)xp_malloc(sizeof(struct xp_file_struct));
						if (dfs->extra_data != NULL)
						{
							dazuko_bzero(dfs->extra_data, sizeof(struct xp_file_struct));

							dfs->extra_data->fd = p->p_retval[0];
							dfs->extra_data->p = p;

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

	return error;
}

DAZUKO_SYSCALL_WRAPPER(dup2)
#endif

#if defined(ON_CLOSE_SUPPORT) || defined(ON_CLOSE_MODIFIED_SUPPORT)
static inline int freebsd_dazuko_sys_close_inner(struct proc *p, struct close_args *uap)
{
	/* The kernel wants to close the given file
	 * descriptor. */

	struct dazuko_file_struct	*dfs = NULL;
	int				error = 0;
	int				check_error = 0;
	struct event_properties		event_p;
	struct xp_daemon_id		xp_id;

	if (p == NULL)
	{
		xp_print("dazuko: warning: freebsd_dazuko_sys_close(NULL, ...)\n");
		check_error = -1;
	}
	else
	{
		freebsd_setupid(&xp_id, p);
		check_error = dazuko_check_access(DAZUKO_ON_CLOSE, 1, &xp_id, NULL);
	}

	if (!check_error)
	{
		if (uap == NULL)
		{
			check_error = -1;
		}
		else if (p->p_cred == NULL)
		{
			check_error = -1;
		}
		else
		{
			dazuko_bzero(&event_p, sizeof(event_p));

			event_p.pid = p->p_pid;
			event_p.set_pid = 1;
			event_p.uid = p->p_cred->p_ruid;
			event_p.set_uid = 1;

			dfs = (struct dazuko_file_struct *)xp_malloc(sizeof(struct dazuko_file_struct));
			if (dfs != NULL)
			{
				dazuko_bzero(dfs, sizeof(struct dazuko_file_struct));

				dfs->extra_data = (struct xp_file_struct *)xp_malloc(sizeof(struct xp_file_struct));
				if (dfs->extra_data != NULL)
				{
					dazuko_bzero(dfs->extra_data, sizeof(struct xp_file_struct));

					dfs->extra_data->fd = uap->fd;
					dfs->extra_data->p = p;

					check_error = xp_fill_file_struct(dfs);
				}
				else
				{
					xp_free(dfs);
					dfs = NULL;
				}
			}
		}
	}

	error = original_sys_close(p, uap);

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

DAZUKO_SYSCALL_WRAPPER(close)
#endif

static inline int freebsd_dazuko_sys_generic(int event, struct proc *p, const char *user_filename, int daemon_is_allowed)
{
	struct dazuko_file_struct	*dfs = NULL;
	struct event_properties		event_p;
	struct xp_daemon_id		xp_id;
	int				error = 0;
	int				check_error = 0;
	struct slot_list		*sl = NULL;

	if (p == NULL)
		return -1;

	freebsd_setupid(&xp_id, p);

	check_error = dazuko_check_access(event, daemon_is_allowed, &xp_id, &sl);

	if (!check_error)
	{
		if (user_filename == NULL)
		{
			xp_print("dazuko: warning: freebsd_dazuko_sys_generic(%d, p, %s)\n", event, user_filename ? "user_filename" : "NULL");
			check_error = -1;
		}
		else if (p->p_cred == NULL)
		{
			xp_print("dazuko: warning: freebsd_dazuko_sys_generic.p->p_cred=NULL\n");
			check_error = -1;
		}
		else
		{
			dazuko_bzero(&event_p, sizeof(event_p));
			event_p.pid = p->p_pid;
			event_p.set_pid = 1;
			event_p.uid = p->p_cred->p_ruid;
			event_p.set_uid = 1;

			dfs = (struct dazuko_file_struct *)xp_malloc(sizeof(struct dazuko_file_struct));
			if (dfs != NULL)
			{
				dazuko_bzero(dfs, sizeof(struct dazuko_file_struct));

				dfs->extra_data = (struct xp_file_struct *)xp_malloc(sizeof(struct xp_file_struct));
				if (dfs->extra_data != NULL)
				{
					dazuko_bzero(dfs->extra_data, sizeof(struct xp_file_struct));

					dfs->extra_data->user_filename = user_filename;
					dfs->extra_data->p = p;

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
	}

	return error;
}

#ifdef ON_EXEC_SUPPORT
static inline int freebsd_dazuko_sys_execve_inner(struct proc *p, struct execve_args *uap)
{
	int error;

	error = freebsd_dazuko_sys_generic(DAZUKO_ON_EXEC, p, uap->fname, 0);

	if (error)
		return error;

	return original_sys_execve(p, uap);
}

DAZUKO_SYSCALL_WRAPPER(execve)
#endif

#ifdef ON_UNLINK_SUPPORT
static inline int freebsd_dazuko_sys_unlink_inner(struct proc *p, struct unlink_args *uap)
{
	int	error;

	error = freebsd_dazuko_sys_generic(DAZUKO_ON_UNLINK, p, uap->path, 1);

	if (error)
		return error;

	return original_sys_unlink(p, uap);
}

DAZUKO_SYSCALL_WRAPPER(unlink)
#endif

#ifdef ON_RMDIR_SUPPORT
static inline int freebsd_dazuko_sys_rmdir_inner(struct proc *p, struct rmdir_args *uap)
{
	int	error;

	error = freebsd_dazuko_sys_generic(DAZUKO_ON_RMDIR, p, uap->path, 1);

	if (error)
		return error;

	return original_sys_rmdir(p, uap);
}

DAZUKO_SYSCALL_WRAPPER(rmdir)
#endif


/* system hook */

#define DAZUKO_HOOK(syscall_func) do \
{ \
	if (sysent[SYS_##syscall_func].sy_narg != freebsd_dazuko_sys_##syscall_func##_sysent.sy_narg) \
	{ \
		DPRINT(("dazuko: incompatible " #syscall_func " syscall narg\n")); \
	} \
	else \
	{ \
		original_sys_##syscall_func = sysent[SYS_##syscall_func].sy_call; \
		sysent[SYS_##syscall_func].sy_call = freebsd_dazuko_sys_##syscall_func##_sysent.sy_call; \
		DPRINT(("dazuko: hooked sys_" #syscall_func "\n")); \
	} \
} \
while (0)

inline int xp_sys_hook()
{
	sdev = make_dev(&cdepts, 0, UID_ROOT, GID_WHEEL, 0600, DEVICE_NAME);

#if defined(ON_OPEN_SUPPORT) || defined(ON_CLOSE_SUPPORT) || defined(ON_CLOSE_MODIFIED_SUPPORT)
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

	return 0;
}

#define DAZUKO_UNHOOK(syscall_func) do \
{ \
	if (original_sys_##syscall_func != NULL) \
	{ \
		if (sysent[SYS_##syscall_func].sy_call != freebsd_dazuko_sys_##syscall_func##_sysent.sy_call) \
			xp_print("dazuko: " #syscall_func " system call has been changed (system may be left in an unstable state!)\n"); \
		sysent[SYS_##syscall_func].sy_call = (sy_call_t*)original_sys_##syscall_func; \
		DPRINT(("dazuko: unhooked sys_" #syscall_func "\n")); \
	} \
} \
while (0)

inline int xp_sys_unhook()
{
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

	while (syscall_in_use > 0)
	{
		DPRINT(("syscall still in use, yielding (%d)\n", syscall_in_use));
		yield(curproc, NULL);
	}

	destroy_dev(sdev);

	return 0;
}


/* output */

int xp_print(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);

	return 0;
}


/* device file operations */

int freebsd_dazuko_device_open(dev_t dev, int oflags, int devtype, struct proc *p)
{
	DPRINT(("dazuko: freebsd_dazuko_device_open() [%d]\n", p->p_pid));

	return 0;
}

static int read_dev_major(struct uio *uio)
{
	size_t	dev_major_len;
	char	tmp[32];

	if (dev_major < 0)
		return ENODEV;

	if (uio->uio_offset != 0)
		return 0;

	/* print dev_major to a string
 	* and get length */
	dazuko_bzero(tmp, sizeof(tmp));

	dev_major_len = dazuko_snprintf(tmp, sizeof(tmp), "%d", dev_major);

	if (tmp[sizeof(tmp)-1] != 0)
	{
		xp_print("dazuko: failing device_read, device number overflow for dameon %d (dev_major=%d)\n", uio->uio_procp->p_pid, dev_major);
		return EFAULT;
	}

	if (uio->uio_iov == NULL)
	{
		xp_print("dazuko: error: freebsd_dazuko_device_read.uio->uio_iov=NULL\n");
		return EFAULT;
	}

	if (uio->uio_iov->iov_len < dev_major_len)
		return EINVAL;

	/* copy dev_major string to userspace */
	if (uiomove(tmp, dev_major_len, uio) != 0)
		return EFAULT;

	return 0;
}

int freebsd_dazuko_device_read(dev_t dev, struct uio *uio, int ioflag)
{
	struct xp_daemon_id	xp_id;

	if (uio == NULL)
	{
		xp_print("dazuko: error: freebsd_dazuko_device_read(..., NULL, ...)\n");
		return EFAULT;
	}

	if (uio->uio_procp == NULL)
	{
		xp_print("dazuko: error: freebsd_dazuko_device_read.uio->uio_procp=NULL\n");
		return EFAULT;
	}

	if (uio->uio_procp->p_cred == NULL)
	{
		xp_print("dazuko: error: freebsd_dazuko_device_read.uio->uio_procp->p_cred=NULL\n");
		return EFAULT;
	}

	DPRINT(("dazuko: freebsd_dazuko_device_read() [%d]\n", uio->uio_procp->p_pid));

	freebsd_setupid(&xp_id, uio->uio_procp);

	/* return dev_major if process is not registered */
	if (!dazuko_is_our_daemon(&xp_id, NULL, NULL))
		return read_dev_major(uio);

	return 0;
}

int freebsd_dazuko_device_write(dev_t dev, struct uio *uio, int ioflag)
{
	struct xp_daemon_id	xp_id;
	char			buffer[32];
	int			size;

	if (uio == NULL)
	{
		xp_print("dazuko: error: freebsd_dazuko_device_write(..., NULL, ...)\n");
		return EFAULT;
	}

	if (uio->uio_procp == NULL)
	{
		xp_print("dazuko: error: freebsd_dazuko_device_write.uio->uio_procp=NULL\n");
		return EFAULT;
	}

	if (uio->uio_procp->p_cred == NULL)
	{
		xp_print("dazuko: error: freebsd_dazuko_device_write.uio->uio_procp->p_cred=NULL\n");
		return EFAULT;
	}

	size = uio->uio_resid;
	if (size >= sizeof(buffer))
		size = sizeof(buffer) - 1;

	/* copy request_pointer string to kernelspace */
	if (uiomove(buffer, size, uio) != 0)
	{
		xp_print("dazuko: error: freebsd_dazuko_device_write.uiomove!=0\n");
		return EFAULT;
	}

	buffer[size] = 0;

	freebsd_setupid(&xp_id, uio->uio_procp);

	if (dazuko_handle_user_request(buffer, &xp_id) == 0)
		return uio->uio_resid;
	else
		return EINTR;
}

int freebsd_dazuko_device_close(dev_t dev, int fflag, int devtype, struct proc *p)
{
	struct xp_daemon_id	xp_id;

	DPRINT(("dazuko: dazuko_device_close() [%d]\n", p->p_pid));

	freebsd_setupid(&xp_id, p);

	/* note: This only works for compat1 mode.
	 * For 1.3, the daemon must properly unregister.
	 */

	return dazuko_unregister_daemon(&xp_id);
}


/* init/exit */

static int dazuko_loader(struct module *m, int what, void *arg)
{
	int			err = 0;
	struct nameidata	nd;

	switch (what)
	{
		case MOD_LOAD:
			err = dazuko_init();

			if (!err)
			{
				NDINIT(&nd, LOOKUP, NOFOLLOW, UIO_SYSSPACE, "/", curproc);

				if (namei(&nd) != 0)
				{
					xp_print("dazuko: warning: failed to get root mount\n");
				}
				else
				{
					orig_rootmnt = nd.ni_rootdir;
					vref(orig_rootmnt);

					/* deref looked up vnode */
					NDFREE(&nd, 0);
				}
			}
			break;

		case MOD_UNLOAD:
			if (dazuko_exit() != 0)
				err = EPERM;

			if (orig_rootmnt != NULL)
				vrele(orig_rootmnt);

			break;

		default:
			err = EINVAL;
			break;
	}

	return err;
}

DEV_MODULE(dazuko, dazuko_loader, NULL);

