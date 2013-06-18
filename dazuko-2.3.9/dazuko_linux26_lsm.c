/* Dazuko Linux LSM. Provide LSM interface for Linux 2.6.
   Written by John Ogness <dazukocode@ogness.net>

   Copyright (c) 2004, 2005, 2006 H+BEDV Datentechnik GmbH
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

#include "dazuko_linux26_lsm.h"


int dazuko_sys_generic(struct inode *inode, int mask, struct nameidata *nd);


#define RETURN_DAZUKO_LSM_CALL(func, args) \
if (dazuko_security_ops.func != NULL) return dazuko_security_ops.func args; \
else if (dazuko_security_default_ops.func != NULL) return dazuko_security_default_ops.func args

#define VOID_DAZUKO_LSM_CALL(func, args) \
if (dazuko_security_ops.func != NULL) dazuko_security_ops.func args; \
else if (dazuko_security_default_ops.func != NULL) dazuko_security_default_ops.func args


int dazuko_security_register_security (const char *name, struct security_operations *ops)
{
	RETURN_DAZUKO_LSM_CALL(register_security, (name, ops));

	return 0;
}

int dazuko_security_unregister_security (const char *name, struct security_operations *ops)
{
	RETURN_DAZUKO_LSM_CALL(unregister_security, (name, ops));

	return 0;
}

#ifndef NO_CAPABILITIES
int dazuko_security_ptrace (struct task_struct *parent, struct task_struct * child)
{
	RETURN_DAZUKO_LSM_CALL(ptrace, (parent, child));

	return cap_ptrace (parent, child);
}
#endif

#ifndef NO_CAPABILITIES
int dazuko_security_capget (struct task_struct *target, kernel_cap_t *effective, kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	RETURN_DAZUKO_LSM_CALL(capget, (target, effective, inheritable, permitted));

	return cap_capget (target, effective, inheritable, permitted);
}
#endif

#ifndef NO_CAPABILITIES
int dazuko_security_capset_check (struct task_struct *target, kernel_cap_t *effective, kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	RETURN_DAZUKO_LSM_CALL(capset_check, (target, effective, inheritable, permitted));

	return cap_capset_check (target, effective, inheritable, permitted);
}
#endif

#ifndef NO_CAPABILITIES
void dazuko_security_capset_set (struct task_struct *target, kernel_cap_t *effective, kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	VOID_DAZUKO_LSM_CALL(capset_set, (target, effective, inheritable, permitted));
	else

	cap_capset_set (target, effective, inheritable, permitted);
}
#endif

int dazuko_security_acct (struct file *file)
{
	RETURN_DAZUKO_LSM_CALL(acct, (file));

	return 0;
}

#ifndef NO_CAPABILITIES
int dazuko_security_capable(struct task_struct * tsk, int cap)
{
	RETURN_DAZUKO_LSM_CALL(capable, (tsk, cap));

	return cap_capable(tsk, cap);
}
#endif

#if defined(LSM_security_sysctl_2_6_10)
int dazuko_security_sysctl(struct ctl_table * table, int op)
#else
int dazuko_security_sysctl(ctl_table * table, int op)
#endif
{
	RETURN_DAZUKO_LSM_CALL(sysctl, (table, op));

	return 0;
}

int dazuko_security_quotactl (int cmds, int type, int id, struct super_block * sb)
{
	RETURN_DAZUKO_LSM_CALL(quotactl, (cmds, type, id, sb));

	return 0;
}

#if defined(LSM_security_quota_on_2_6_11)
int dazuko_security_quota_on (struct dentry * dentry)
{
	RETURN_DAZUKO_LSM_CALL(quota_on, (dentry));

	return 0;
}
#else
int dazuko_security_quota_on (struct file * file)
{
	RETURN_DAZUKO_LSM_CALL(quota_on, (file));

	return 0;
}
#endif

#ifndef NO_CAPABILITIES
int dazuko_security_syslog(int type)
{
	RETURN_DAZUKO_LSM_CALL(syslog, (type));

	return cap_syslog(type);
}
#endif

#ifndef NO_CAPABILITIES
#if defined(LSM_security_settime_2_6_10)
int dazuko_security_settime(struct timespec *ts, struct timezone *tz)
{
	RETURN_DAZUKO_LSM_CALL(settime, (ts, tz));

	return cap_settime(ts, tz);
}
#endif
#endif

#ifndef NO_CAPABILITIES
#if defined(LSM_security_vm_enough_memory_2_6_23)
int dazuko_security_vm_enough_memory(struct mm_struct *mm, long pages)
{
	RETURN_DAZUKO_LSM_CALL(vm_enough_memory, (mm, pages));

	return cap_vm_enough_memory(mm, pages);
}
#else
int dazuko_security_vm_enough_memory(long pages)
{
	RETURN_DAZUKO_LSM_CALL(vm_enough_memory, (pages));

	return cap_vm_enough_memory(pages);
}
#endif
#endif

int dazuko_security_bprm_alloc_security (struct linux_binprm *bprm)
{
	RETURN_DAZUKO_LSM_CALL(bprm_alloc_security, (bprm));

	return 0;
}

void dazuko_security_bprm_free_security (struct linux_binprm *bprm)
{
	VOID_DAZUKO_LSM_CALL(bprm_free_security, (bprm));
}

#ifndef NO_CAPABILITIES
#if defined(LSM_security_bprm_apply_creds_2_6_6)
void dazuko_security_bprm_apply_creds (struct linux_binprm *bprm, int unsafe)
{ 
	VOID_DAZUKO_LSM_CALL(bprm_apply_creds, (bprm, unsafe));
	else

	cap_bprm_apply_creds (bprm, unsafe);
}
#elif defined(LSM_security_bprm_apply_creds_2_6_6_mandrake)
void dazuko_security_bprm_apply_creds (struct linux_binprm *bprm)
{ 
	VOID_DAZUKO_LSM_CALL(bprm_apply_creds, (bprm));
	else

	cap_bprm_apply_creds (bprm);
}
#else
void dazuko_security_bprm_compute_creds (struct linux_binprm *bprm)
{ 
	VOID_DAZUKO_LSM_CALL(bprm_compute_creds, (bprm));
	else

	cap_bprm_compute_creds (bprm);
}
#endif
#endif

#if defined(LSM_security_bprm_post_apply_creds_2_6_11)
void dazuko_security_bprm_post_apply_creds (struct linux_binprm * bprm)
{
	VOID_DAZUKO_LSM_CALL(bprm_post_apply_creds, (bprm));
}
#endif

#ifndef NO_CAPABILITIES
int dazuko_security_bprm_set_security (struct linux_binprm *bprm)
{
	RETURN_DAZUKO_LSM_CALL(bprm_set_security, (bprm));

	return cap_bprm_set_security (bprm);
}
#endif

int dazuko_security_bprm_check_security (struct linux_binprm *bprm)
{
	RETURN_DAZUKO_LSM_CALL(bprm_check_security, (bprm));

	return 0;
}

#ifndef NO_CAPABILITIES
int dazuko_security_bprm_secureexec (struct linux_binprm *bprm)
{
	RETURN_DAZUKO_LSM_CALL(bprm_secureexec, (bprm));

	return cap_bprm_secureexec(bprm);
}
#endif

int dazuko_security_sb_alloc_security (struct super_block *sb)
{
	RETURN_DAZUKO_LSM_CALL(sb_alloc_security, (sb));

	return 0;
}

void dazuko_security_sb_free_security (struct super_block *sb)
{
	VOID_DAZUKO_LSM_CALL(sb_free_security, (sb));
}

#if defined(LSM_security_sb_copy_data_2_6_5)
int dazuko_security_sb_copy_data (struct file_system_type *type, void *orig, void *copy)
{
	RETURN_DAZUKO_LSM_CALL(sb_copy_data, (type, orig, copy));

	return 0;
}
#elif defined(LSM_security_sb_copy_data_2_6_3)
int dazuko_security_sb_copy_data (const char *fstype, void *orig, void *copy)
{
	RETURN_DAZUKO_LSM_CALL(sb_copy_data, (fstype, orig, copy));

	return 0;
}
#endif

#if defined(LSM_security_sb_kern_mount_2_6_3)
int dazuko_security_sb_kern_mount (struct super_block *sb, void *data)
{
	RETURN_DAZUKO_LSM_CALL(sb_kern_mount, (sb, data));

	return 0;
}
#else
int dazuko_security_sb_kern_mount (struct super_block *sb)
{
	RETURN_DAZUKO_LSM_CALL(sb_kern_mount, (sb));

	return 0;
}
#endif

#if defined(LSM_security_sb_statfs_2_6_18)
int dazuko_security_sb_statfs (struct dentry *dentry)
{
	RETURN_DAZUKO_LSM_CALL(sb_statfs, (dentry));

	return 0;
}
#else
int dazuko_security_sb_statfs (struct super_block *sb)
{
	RETURN_DAZUKO_LSM_CALL(sb_statfs, (sb));

	return 0;
}
#endif

int dazuko_security_sb_mount (char *dev_name, struct nameidata *nd, char *type, unsigned long flags, void *data)
{
	RETURN_DAZUKO_LSM_CALL(sb_mount, (dev_name, nd, type, flags, data));

	return 0;
}

int dazuko_security_sb_check_sb (struct vfsmount *mnt, struct nameidata *nd)
{
	RETURN_DAZUKO_LSM_CALL(sb_check_sb, (mnt, nd));

	return 0;
}

int dazuko_security_sb_umount (struct vfsmount *mnt, int flags)
{
	RETURN_DAZUKO_LSM_CALL(sb_umount, (mnt, flags));

	return 0;
}

void dazuko_security_sb_umount_close (struct vfsmount *mnt)
{
	VOID_DAZUKO_LSM_CALL(sb_umount_close, (mnt));
}

void dazuko_security_sb_umount_busy (struct vfsmount *mnt)
{
	VOID_DAZUKO_LSM_CALL(sb_umount_busy, (mnt));
}

void dazuko_security_sb_post_remount (struct vfsmount *mnt, unsigned long flags, void *data)
{
	VOID_DAZUKO_LSM_CALL(sb_post_remount, (mnt, flags, data));
}

void dazuko_security_sb_post_mountroot (void)
{
	VOID_DAZUKO_LSM_CALL(sb_post_mountroot, ());
}

void dazuko_security_sb_post_addmount (struct vfsmount *mnt, struct nameidata *mountpoint_nd)
{
	VOID_DAZUKO_LSM_CALL(sb_post_addmount, (mnt, mountpoint_nd));
}

int dazuko_security_sb_pivotroot (struct nameidata *old_nd, struct nameidata *new_nd)
{
	RETURN_DAZUKO_LSM_CALL(sb_pivotroot, (old_nd, new_nd));

	return 0;
}

void dazuko_security_sb_post_pivotroot (struct nameidata *old_nd, struct nameidata *new_nd)
{
	VOID_DAZUKO_LSM_CALL(sb_post_pivotroot, (old_nd, new_nd));
}

int dazuko_security_inode_alloc_security (struct inode *inode)
{
	RETURN_DAZUKO_LSM_CALL(inode_alloc_security, (inode));

	return 0;
}

void dazuko_security_inode_free_security (struct inode *inode)
{
	VOID_DAZUKO_LSM_CALL(inode_free_security, (inode));
}

#if defined(LSM_security_inode_init_security_2_6_14)
int dazuko_security_inode_init_security (struct inode *inode, struct inode *dir, char **name, void **value, size_t *len)
{
	RETURN_DAZUKO_LSM_CALL(inode_init_security, (inode, dir, name, value, len));

	return -EOPNOTSUPP;
}
#endif
	
#if defined(LSM_security_inode_create_2_6_21)
int dazuko_security_inode_create (struct inode *dir, struct dentry *dentry, struct vfsmount *mnt, int mode)
{
	RETURN_DAZUKO_LSM_CALL(inode_create, (dir, dentry, mnt, mode));

	return 0;
}
#else
int dazuko_security_inode_create (struct inode *dir, struct dentry *dentry, int mode)
{
	RETURN_DAZUKO_LSM_CALL(inode_create, (dir, dentry, mode));

	return 0;
}
#endif

#if defined(LSM_security_inode_post_create_2_6_14)
void dazuko_security_inode_post_create (struct inode *dir, struct dentry *dentry, int mode)
{
	VOID_DAZUKO_LSM_CALL(inode_post_create, (dir, dentry, mode));
}
#endif

#if defined(LSM_security_inode_link_2_6_21)
int dazuko_security_inode_link (struct dentry *old_dentry, struct vfsmount *old_mnt, struct inode *dir, struct dentry *new_dentry, struct vfsmount *new_mnt)
{
	RETURN_DAZUKO_LSM_CALL(inode_link, (old_dentry, old_mnt, dir, new_dentry, new_mnt));

	return 0;
}
#else
int dazuko_security_inode_link (struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	RETURN_DAZUKO_LSM_CALL(inode_link, (old_dentry, dir, new_dentry));

	return 0;
}
#endif

#if defined(LSM_security_inode_post_link_2_6_14)
void dazuko_security_inode_post_link (struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	VOID_DAZUKO_LSM_CALL(inode_post_link, (old_dentry, dir, new_dentry));
}
#endif

#if defined(LSM_security_inode_unlink_2_6_21)
int dazuko_security_inode_unlink (struct inode *dir, struct dentry *dentry, struct vfsmount *mnt)
{
	RETURN_DAZUKO_LSM_CALL(inode_unlink, (dir, dentry, mnt));

	return 0;
}
#else
int dazuko_security_inode_unlink (struct inode *dir, struct dentry *dentry)
{
	RETURN_DAZUKO_LSM_CALL(inode_unlink, (dir, dentry));

	return 0;
}
#endif

#if defined(LSM_security_inode_symlink_2_6_21)
int dazuko_security_inode_symlink (struct inode *dir, struct dentry *dentry, struct vfsmount *mnt, const char *old_name)
{
	RETURN_DAZUKO_LSM_CALL(inode_symlink, (dir, dentry, mnt, old_name));

	return 0;
}
#else
int dazuko_security_inode_symlink (struct inode *dir, struct dentry *dentry, const char *old_name)
{
	RETURN_DAZUKO_LSM_CALL(inode_symlink, (dir, dentry, old_name));

	return 0;
}
#endif

#if defined(LSM_security_inode_post_symlink_2_6_14)
void dazuko_security_inode_post_symlink (struct inode *dir, struct dentry *dentry, const char *old_name)
{
	VOID_DAZUKO_LSM_CALL(inode_post_symlink, (dir, dentry, old_name));
}
#endif

#if defined(LSM_security_inode_mkdir_2_6_21)
int dazuko_security_inode_mkdir (struct inode *dir, struct dentry *dentry, struct vfsmount *mnt, int mode)
{
	RETURN_DAZUKO_LSM_CALL(inode_mkdir, (dir, dentry, mnt, mode));

	return 0;
}
#else
int dazuko_security_inode_mkdir (struct inode *dir, struct dentry *dentry, int mode)
{
	RETURN_DAZUKO_LSM_CALL(inode_mkdir, (dir, dentry, mode));

	return 0;
}
#endif

#if defined(LSM_security_inode_post_mkdir_2_6_14)
void dazuko_security_inode_post_mkdir (struct inode *dir, struct dentry *dentry, int mode)
{
	VOID_DAZUKO_LSM_CALL(inode_post_mkdir, (dir, dentry, mode));
}
#endif

#if defined(LSM_security_inode_rmdir_2_6_21)
int dazuko_security_inode_rmdir (struct inode *dir, struct dentry *dentry, struct vfsmount *mnt)
{
	RETURN_DAZUKO_LSM_CALL(inode_rmdir, (dir, dentry, mnt));

	return 0;
}
#else
int dazuko_security_inode_rmdir (struct inode *dir, struct dentry *dentry)
{
	RETURN_DAZUKO_LSM_CALL(inode_rmdir, (dir, dentry));

	return 0;
}
#endif

#if defined(LSM_security_inode_mknod_2_6_21)
int dazuko_security_inode_mknod (struct inode *dir, struct dentry *dentry, struct vfsmount *mnt, int mode, dev_t dev)
{
	RETURN_DAZUKO_LSM_CALL(inode_mknod, (dir, dentry, mnt, mode, dev));

	return 0;
}
#else
int dazuko_security_inode_mknod (struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
{
	RETURN_DAZUKO_LSM_CALL(inode_mknod, (dir, dentry, mode, dev));

	return 0;
}
#endif

#if defined(LSM_security_inode_post_mknod_2_6_14)
void dazuko_security_inode_post_mknod (struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
{
	VOID_DAZUKO_LSM_CALL(inode_post_mknod, (dir, dentry, mode, dev));
}
#endif

#if defined(LSM_security_inode_rename_2_6_21)
int dazuko_security_inode_rename (struct inode *old_dir, struct dentry *old_dentry, struct vfsmount *old_mnt, struct inode *new_dir, struct dentry *new_dentry, struct vfsmount *new_mnt)
{
	RETURN_DAZUKO_LSM_CALL(inode_rename, (old_dir, old_dentry, old_mnt, new_dir, new_dentry, new_mnt));

	return 0;
}
#else
int dazuko_security_inode_rename (struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry)
{
	RETURN_DAZUKO_LSM_CALL(inode_rename, (old_dir, old_dentry, new_dir, new_dentry));

	return 0;
}
#endif

#if defined(LSM_security_inode_post_rename_2_6_14)
void dazuko_security_inode_post_rename (struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry)
{
	VOID_DAZUKO_LSM_CALL(inode_post_rename, (old_dir, old_dentry, new_dir, new_dentry));
}
#endif

#if defined(LSM_security_inode_readlink_2_6_21)
int dazuko_security_inode_readlink (struct dentry *dentry, struct vfsmount *mnt)
{
	RETURN_DAZUKO_LSM_CALL(inode_readlink, (dentry, mnt));

	return 0;
}
#else
int dazuko_security_inode_readlink (struct dentry *dentry)
{
	RETURN_DAZUKO_LSM_CALL(inode_readlink, (dentry));

	return 0;
}
#endif

int dazuko_security_inode_follow_link (struct dentry *dentry, struct nameidata *nd)
{
	RETURN_DAZUKO_LSM_CALL(inode_follow_link, (dentry, nd));

	return 0;
}

int dazuko_security_inode_permission (struct inode *inode, int mask, struct nameidata *nd)
{ 
	int	rc1;
	int	rc2;

	/* get Dazuko's decision */
	rc1 = dazuko_sys_generic(inode, mask, nd);

	if (dazuko_security_ops.inode_permission != NULL)
	{
		/* get a stacked module's decision (regardless of Dazuko's decision) */
		rc2 = dazuko_security_ops.inode_permission (inode, mask, nd);

		/* Dazuko's decision has priority if non-zero */
		if (rc1 != 0)
			return rc1;

		return rc2;
	}

	/* return Dazuko's decision if non-zero */
	if (rc1 != 0)
		return rc1;

	/* call default hook, if available */
	if (dazuko_security_default_ops.inode_permission != NULL)
		return dazuko_security_default_ops.inode_permission (inode, mask, nd);

	return 0;
}

#if defined(LSM_security_inode_setattr_2_6_21)
int dazuko_security_inode_setattr (struct dentry *dentry, struct vfsmount *mnt, struct iattr *attr)
{
	RETURN_DAZUKO_LSM_CALL(inode_setattr, (dentry, mnt, attr));

	return 0;
}
#else
int dazuko_security_inode_setattr (struct dentry *dentry, struct iattr *attr)
{
	RETURN_DAZUKO_LSM_CALL(inode_setattr, (dentry, attr));

	return 0;
}
#endif

int dazuko_security_inode_getattr (struct vfsmount *mnt, struct dentry *dentry)
{
	RETURN_DAZUKO_LSM_CALL(inode_getattr, (mnt, dentry));

	return 0;
}

void dazuko_security_inode_delete (struct inode *inode)
{
	VOID_DAZUKO_LSM_CALL(inode_delete, (inode));
}

#ifndef NO_CAPABILITIES
#if defined(LSM_security_inode_setxattr_2_6_21)
int dazuko_security_inode_setxattr (struct dentry *dentry, struct vfsmount *mnt, char *name, void *value, size_t size, int flags, struct file *file)
{
	RETURN_DAZUKO_LSM_CALL(inode_setxattr, (dentry, mnt, name, value, size, flags, file));

	return 0;
}
#else
int dazuko_security_inode_setxattr (struct dentry *dentry, char *name, void *value, size_t size, int flags)
{
	RETURN_DAZUKO_LSM_CALL(inode_setxattr, (dentry, name, value, size, flags));

#if defined(LSM_security_inode_setxattr_2_6_2)
	return cap_inode_setxattr(dentry, name, value, size, flags);
#else
	return 0;
#endif
}
#endif
#endif

#if defined(LSM_security_inode_post_setxattr_2_6_21)
void dazuko_security_inode_post_setxattr (struct dentry *dentry, struct vfsmount *mnt, char *name, void *value, size_t size, int flags)
{
	VOID_DAZUKO_LSM_CALL(inode_post_setxattr, (dentry, mnt, name, value, size, flags));
}
#else
void dazuko_security_inode_post_setxattr (struct dentry *dentry, char *name, void *value, size_t size, int flags)
{
	VOID_DAZUKO_LSM_CALL(inode_post_setxattr, (dentry, name, value, size, flags));
}
#endif

#if defined(LSM_security_inode_getxattr_2_6_21)
int dazuko_security_inode_getxattr (struct dentry *dentry, struct vfsmount *mnt, char *name, struct file *file)
{
	RETURN_DAZUKO_LSM_CALL(inode_getxattr, (dentry, mnt, name, file));

	return 0;
}
#else
int dazuko_security_inode_getxattr (struct dentry *dentry, char *name)
{
	RETURN_DAZUKO_LSM_CALL(inode_getxattr, (dentry, name));

	return 0;
}
#endif

#if defined(LSM_security_inode_listxattr_2_6_21)
int dazuko_security_inode_listxattr (struct dentry *dentry, struct vfsmount *mnt, struct file *file)
{
	RETURN_DAZUKO_LSM_CALL(inode_listxattr, (dentry, mnt, file));

	return 0;
}
#else
int dazuko_security_inode_listxattr (struct dentry *dentry)
{
	RETURN_DAZUKO_LSM_CALL(inode_listxattr, (dentry));

	return 0;
}
#endif

#ifndef NO_CAPABILITIES
#if defined(LSM_security_inode_removexattr_2_6_21)
int dazuko_security_inode_removexattr (struct dentry *dentry, struct vfsmount *mnt, char *name, struct file *file)
{
	RETURN_DAZUKO_LSM_CALL(inode_removexattr, (dentry, mnt, name, file));

	return 0;
}
#else
int dazuko_security_inode_removexattr (struct dentry *dentry, char *name)
{
	RETURN_DAZUKO_LSM_CALL(inode_removexattr, (dentry, name));

#if defined(LSM_security_inode_removexattr_2_6_2)
	return cap_inode_removexattr(dentry, name);
#else
	return 0;
#endif
}
#endif
#endif

#if defined(LSM_security_inode_xattr_getsuffix_2_6_17)
const char * dazuko_security_inode_xattr_getsuffix (void)
{
	RETURN_DAZUKO_LSM_CALL(inode_xattr_getsuffix, ());

	return NULL;
}
#endif

#if defined(LSM_security_inode_getsecurity_2_6_10)
int dazuko_security_inode_getsecurity(struct inode *inode, const char *name, void *buffer, size_t size)
{
	RETURN_DAZUKO_LSM_CALL(inode_getsecurity, (inode, name, buffer, size));

	return -EOPNOTSUPP;
}
#elif defined(LSM_security_inode_getsecurity_2_6_17)
int dazuko_security_inode_getsecurity(const struct inode *inode, const char *name, void *buffer, size_t size, int err)
{
	RETURN_DAZUKO_LSM_CALL(inode_getsecurity, (inode, name, buffer, size, err));

	return -EOPNOTSUPP;
}
#elif defined(LSM_security_inode_getsecurity_2_6_14)
int dazuko_security_inode_getsecurity(struct inode *inode, const char *name, void *buffer, size_t size, int err)
{
	RETURN_DAZUKO_LSM_CALL(inode_getsecurity, (inode, name, buffer, size, err));

	return -EOPNOTSUPP;
}
#else
int dazuko_security_inode_getsecurity(struct dentry *dentry, const char *name, void *buffer, size_t size)
{
	RETURN_DAZUKO_LSM_CALL(inode_getsecurity, (dentry, name, buffer, size));

	return -EOPNOTSUPP;
}
#endif

#if defined(LSM_security_inode_setsecurity_2_6_10)
int dazuko_security_inode_setsecurity(struct inode *inode, const char *name, const void *value, size_t size, int flags)
{
	RETURN_DAZUKO_LSM_CALL(inode_setsecurity, (inode, name, value, size, flags));

	return -EOPNOTSUPP;
}
#else
int dazuko_security_inode_setsecurity(struct dentry *dentry, const char *name, const void *value, size_t size, int flags) 
{
	RETURN_DAZUKO_LSM_CALL(inode_setsecurity, (dentry, name, value, size, flags));

	return -EOPNOTSUPP;
}
#endif

#if defined(LSM_security_inode_listsecurity_2_6_10)
int dazuko_security_inode_listsecurity(struct inode *inode, char *buffer, size_t buffer_size)
{
	RETURN_DAZUKO_LSM_CALL(inode_listsecurity, (inode, buffer, buffer_size));

	return 0;
}
#else
int dazuko_security_inode_listsecurity(struct dentry *dentry, char *buffer)
{
	RETURN_DAZUKO_LSM_CALL(inode_listsecurity, (dentry, buffer));

	return 0;
}
#endif

int dazuko_security_file_permission (struct file *file, int mask)
{
	RETURN_DAZUKO_LSM_CALL(file_permission, (file, mask));

	return 0;
}

int dazuko_security_file_alloc_security (struct file *file)
{
	RETURN_DAZUKO_LSM_CALL(file_alloc_security, (file));

	return 0;
}

void dazuko_security_file_free_security (struct file *file)
{
	VOID_DAZUKO_LSM_CALL(file_free_security, (file));
}

int dazuko_security_file_ioctl (struct file *file, unsigned int cmd, unsigned long arg)
{
	RETURN_DAZUKO_LSM_CALL(file_ioctl, (file, cmd, arg));

	return 0;
}

#if defined(LSM_security_file_mmap_2_6_23)
int dazuko_security_file_mmap (struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags, unsigned long addr, unsigned long addr_only)
{
	RETURN_DAZUKO_LSM_CALL(file_mmap, (file, reqprot, prot, flags, addr, addr_only));

	return 0;
}
#elif defined(LSM_security_file_mmap_2_6_12)
int dazuko_security_file_mmap (struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags)
{
	RETURN_DAZUKO_LSM_CALL(file_mmap, (file, reqprot, prot, flags));

	return 0;
}
#else
int dazuko_security_file_mmap (struct file *file, unsigned long prot, unsigned long flags)
{
	RETURN_DAZUKO_LSM_CALL(file_mmap, (file, prot, flags));

	return 0;
}
#endif

#if defined(LSM_security_file_mprotect_2_6_12)
int dazuko_security_file_mprotect (struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot)
{
	RETURN_DAZUKO_LSM_CALL(file_mprotect, (vma, reqprot, prot));

	return 0;
}
#else
int dazuko_security_file_mprotect (struct vm_area_struct *vma, unsigned long prot)
{
	RETURN_DAZUKO_LSM_CALL(file_mprotect, (vma, prot));

	return 0;
}
#endif

int dazuko_security_file_lock (struct file *file, unsigned int cmd)
{
	RETURN_DAZUKO_LSM_CALL(file_lock, (file, cmd));

	return 0;
}

int dazuko_security_file_fcntl (struct file *file, unsigned int cmd, unsigned long arg)
{
	RETURN_DAZUKO_LSM_CALL(file_fcntl, (file, cmd, arg));

	return 0;
}

int dazuko_security_file_set_fowner (struct file *file)
{
	RETURN_DAZUKO_LSM_CALL(file_set_fowner, (file));

	return 0;
}

#if defined(LSM_security_file_send_sigiotask_2_6_10)
int dazuko_security_file_send_sigiotask (struct task_struct *tsk, struct fown_struct *fown, int sig)
{
	RETURN_DAZUKO_LSM_CALL(file_send_sigiotask, (tsk, fown, sig));

	return 0;
}
#else
int dazuko_security_file_send_sigiotask (struct task_struct *tsk, struct fown_struct *fown, int fd, int reason)
{
	RETURN_DAZUKO_LSM_CALL(file_send_sigiotask, (tsk, fown, fd, reason));

	return 0;
}
#endif

int dazuko_security_file_receive (struct file *file)
{
	RETURN_DAZUKO_LSM_CALL(file_receive, (file));

	return 0;
}

int dazuko_security_task_create (unsigned long clone_flags)
{
	RETURN_DAZUKO_LSM_CALL(task_create, (clone_flags));

	return 0;
}

int dazuko_security_task_alloc_security (struct task_struct *p)
{
	RETURN_DAZUKO_LSM_CALL(task_alloc_security, (p));

	return 0;
}

void dazuko_security_task_free_security (struct task_struct *p)
{
	VOID_DAZUKO_LSM_CALL(task_free_security, (p));
}

int dazuko_security_task_setuid (uid_t id0, uid_t id1, uid_t id2, int flags)
{
	RETURN_DAZUKO_LSM_CALL(task_setuid, (id0, id1, id2, flags));

	return 0;
}

#ifndef NO_CAPABILITIES
int dazuko_security_task_post_setuid (uid_t old_ruid, uid_t old_euid, uid_t old_suid, int flags)
{
	RETURN_DAZUKO_LSM_CALL(task_post_setuid, (old_ruid, old_euid, old_suid, flags));

	return cap_task_post_setuid (old_ruid, old_euid, old_suid, flags);
}
#endif

int dazuko_security_task_setgid (gid_t id0, gid_t id1, gid_t id2, int flags)
{
	RETURN_DAZUKO_LSM_CALL(task_setgid, (id0, id1, id2, flags));

	return 0;
}

int dazuko_security_task_setpgid (struct task_struct *p, pid_t pgid)
{
	RETURN_DAZUKO_LSM_CALL(task_setpgid, (p, pgid));

	return 0;
}

int dazuko_security_task_getpgid (struct task_struct *p)
{
	RETURN_DAZUKO_LSM_CALL(task_getpgid, (p));

	return 0;
}

int dazuko_security_task_getsid (struct task_struct *p)
{
	RETURN_DAZUKO_LSM_CALL(task_getsid, (p));

	return 0;
}

#if defined(LSM_security_task_getsecid_2_6_19)
void dazuko_security_task_getsecid (struct task_struct * p, u32 * secid)
{
	VOID_DAZUKO_LSM_CALL(task_getsecid, (p, secid));
}
#endif

#if defined(LSM_security_task_setioprio_2_6_19)
int dazuko_security_task_setioprio (struct task_struct * p, int ioprio)
{
	RETURN_DAZUKO_LSM_CALL(task_setioprio, (p, ioprio));

	return 0;
}
#endif

#if defined(LSM_security_task_getioprio_2_6_19)
int dazuko_security_task_getioprio (struct task_struct * p)
{
	RETURN_DAZUKO_LSM_CALL(task_getioprio, (p));

	return 0;
}
#endif

#if defined(LSM_security_task_movememory_2_6_19)
int dazuko_security_task_movememory (struct task_struct * p)
{
	RETURN_DAZUKO_LSM_CALL(task_movememory, (p));

	return 0;
}
#endif

#if defined(LSM_security_task_setgroups_2_6_4)
int dazuko_security_task_setgroups (struct group_info *group_info)
{
	RETURN_DAZUKO_LSM_CALL(task_setgroups, (group_info));

	return 0;
}
#else
int dazuko_security_task_setgroups (int gidsetsize, gid_t * grouplist)
{
	RETURN_DAZUKO_LSM_CALL(task_setgroups, (gidsetsize, grouplist));

	return 0;
}
#endif

int dazuko_security_task_setnice (struct task_struct *p, int nice)
{
	RETURN_DAZUKO_LSM_CALL(task_setnice, (p, nice));

	return 0;
}

int dazuko_security_task_setrlimit (unsigned int resource, struct rlimit *new_rlim)
{
	RETURN_DAZUKO_LSM_CALL(task_setrlimit, (resource, new_rlim));

	return 0;
}

int dazuko_security_task_setscheduler (struct task_struct *p, int policy, struct sched_param *lp)
{
	RETURN_DAZUKO_LSM_CALL(task_setscheduler, (p, policy, lp));

	return 0;
}

int dazuko_security_task_getscheduler (struct task_struct *p)
{
	RETURN_DAZUKO_LSM_CALL(task_getscheduler, (p));

	return 0;
}

#if defined(LSM_security_task_kill_2_6_18)
int dazuko_security_task_kill (struct task_struct *p, struct siginfo *info, int sig, u32 secid)
{
	RETURN_DAZUKO_LSM_CALL(task_kill, (p, info, sig, secid));

	return 0;
}
#else
int dazuko_security_task_kill (struct task_struct *p, struct siginfo *info, int sig)
{
	RETURN_DAZUKO_LSM_CALL(task_kill, (p, info, sig));

	return 0;
}
#endif

int dazuko_security_task_wait (struct task_struct *p)
{
	RETURN_DAZUKO_LSM_CALL(task_wait, (p));

	return 0;
}

int dazuko_security_task_prctl (int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	RETURN_DAZUKO_LSM_CALL(task_prctl, (option, arg2, arg3, arg4, arg5));

	return 0;
}

#ifndef NO_CAPABILITIES
void dazuko_security_task_reparent_to_init (struct task_struct *p)
{
	VOID_DAZUKO_LSM_CALL(task_reparent_to_init, (p));
	else

	cap_task_reparent_to_init (p);
}
#endif

void dazuko_security_task_to_inode(struct task_struct *p, struct inode *inode)
{
	VOID_DAZUKO_LSM_CALL(task_to_inode, (p, inode));
}

int dazuko_security_ipc_permission (struct kern_ipc_perm *ipcp, short flag)
{
	RETURN_DAZUKO_LSM_CALL(ipc_permission, (ipcp, flag));

	return 0;
}

#if defined(LSM_security_ipc_getsecurity_2_6_17)
int dazuko_security_ipc_getsecurity (struct kern_ipc_perm *ipcp, void *buffer, size_t size)
{
	RETURN_DAZUKO_LSM_CALL(ipc_getsecurity, (ipcp, buffer, size));

	return -EOPNOTSUPP;
}
#endif

int dazuko_security_msg_msg_alloc_security (struct msg_msg * msg)
{
	RETURN_DAZUKO_LSM_CALL(msg_msg_alloc_security, (msg));

	return 0;
}

void dazuko_security_msg_msg_free_security (struct msg_msg * msg)
{
	VOID_DAZUKO_LSM_CALL(msg_msg_free_security, (msg));
}

int dazuko_security_msg_queue_alloc_security (struct msg_queue *msq)
{
	RETURN_DAZUKO_LSM_CALL(msg_queue_alloc_security, (msq));

	return 0;
}

void dazuko_security_msg_queue_free_security (struct msg_queue *msq)
{
	VOID_DAZUKO_LSM_CALL(msg_queue_free_security, (msq));
}

int dazuko_security_msg_queue_associate (struct msg_queue * msq, int msqflg)
{
	RETURN_DAZUKO_LSM_CALL(msg_queue_associate, (msq, msqflg));

	return 0;
}

int dazuko_security_msg_queue_msgctl (struct msg_queue * msq, int cmd)
{
	RETURN_DAZUKO_LSM_CALL(msg_queue_msgctl, (msq, cmd));

	return 0;
}

int dazuko_security_msg_queue_msgsnd (struct msg_queue * msq, struct msg_msg * msg, int msqflg)
{
	RETURN_DAZUKO_LSM_CALL(msg_queue_msgsnd, (msq, msg, msqflg));

	return 0;
}

int dazuko_security_msg_queue_msgrcv (struct msg_queue * msq, struct msg_msg * msg, struct task_struct * target, long type, int mode)
{
	RETURN_DAZUKO_LSM_CALL(msg_queue_msgrcv, (msq, msg, target, type, mode));

	return 0;
}

int dazuko_security_shm_alloc_security (struct shmid_kernel *shp)
{
	RETURN_DAZUKO_LSM_CALL(shm_alloc_security, (shp));

	return 0;
}

void dazuko_security_shm_free_security (struct shmid_kernel *shp)
{
	VOID_DAZUKO_LSM_CALL(shm_free_security, (shp));
}

int dazuko_security_shm_associate (struct shmid_kernel * shp, int shmflg)
{
	RETURN_DAZUKO_LSM_CALL(shm_associate, (shp, shmflg));

	return 0;
}

int dazuko_security_shm_shmctl (struct shmid_kernel * shp, int cmd)
{
	RETURN_DAZUKO_LSM_CALL(shm_shmctl, (shp, cmd));

	return 0;
}

#if defined(LSM_security_shm_shmat_2_6_7)
int dazuko_security_shm_shmat (struct shmid_kernel * shp, char __user *shmaddr, int shmflg)
#else
int dazuko_security_shm_shmat (struct shmid_kernel * shp, char *shmaddr, int shmflg)
#endif
{
	RETURN_DAZUKO_LSM_CALL(shm_shmat, (shp, shmaddr, shmflg));

	return 0;
}

int dazuko_security_sem_alloc_security (struct sem_array *sma)
{
	RETURN_DAZUKO_LSM_CALL(sem_alloc_security, (sma));

	return 0;
}

void dazuko_security_sem_free_security (struct sem_array *sma)
{
	VOID_DAZUKO_LSM_CALL(sem_free_security, (sma));
}

int dazuko_security_sem_associate (struct sem_array * sma, int semflg)
{
	RETURN_DAZUKO_LSM_CALL(sem_associate, (sma, semflg));

	return 0;
}

int dazuko_security_sem_semctl (struct sem_array * sma, int cmd)
{
	RETURN_DAZUKO_LSM_CALL(sem_semctl, (sma, cmd));

	return 0;
}

int dazuko_security_sem_semop (struct sem_array * sma, struct sembuf * sops, unsigned nsops, int alter)
{
	RETURN_DAZUKO_LSM_CALL(sem_semop, (sma, sops, nsops, alter));

	return 0;
}

void dazuko_security_d_instantiate (struct dentry *dentry, struct inode *inode)
{
	VOID_DAZUKO_LSM_CALL(d_instantiate, (dentry, inode));
}

#if defined(LSM_security_getprocattr_2_6_21)
int dazuko_security_getprocattr(struct task_struct *p, char *name, char **value)
{
	RETURN_DAZUKO_LSM_CALL(getprocattr, (p, name, value));

	return -EINVAL;
}
#else
int dazuko_security_getprocattr(struct task_struct *p, char *name, void *value, size_t size)
{
	RETURN_DAZUKO_LSM_CALL(getprocattr, (p, name, value, size));

	return -EINVAL;
}
#endif

int dazuko_security_setprocattr(struct task_struct *p, char *name, void *value, size_t size)
{
	RETURN_DAZUKO_LSM_CALL(setprocattr, (p, name, value, size));

	return -EINVAL;
}

#if defined(LSM_security_secid_to_secctx_2_6_19)
int dazuko_security_secid_to_secctx(u32 secid, char **secdata, u32 *seclen)
{
	RETURN_DAZUKO_LSM_CALL(secid_to_secctx, (secid, secdata, seclen));

	return -EOPNOTSUPP;
}
#endif

#if defined(LSM_security_release_secctx_2_6_19)
void dazuko_security_release_secctx(char *secdata, u32 seclen)
{
	VOID_DAZUKO_LSM_CALL(release_secctx, (secdata, seclen));
}
#endif

#ifndef NO_CAPABILITIES
#if defined(LSM_security_netlink_send_2_6_8)
int dazuko_security_netlink_send (struct sock *sk, struct sk_buff *skb)
{
	RETURN_DAZUKO_LSM_CALL(netlink_send, (sk, skb));

	return cap_netlink_send (sk, skb);
}
#else
int dazuko_security_netlink_send (struct sk_buff *skb)
{
	RETURN_DAZUKO_LSM_CALL(netlink_send, (skb));

	return cap_netlink_send (skb);
}
#endif
#endif

#ifndef NO_CAPABILITIES
#if defined(LSM_security_netlink_recv_2_6_18)
int dazuko_security_netlink_recv (struct sk_buff *skb, int cap)
{
	RETURN_DAZUKO_LSM_CALL(netlink_recv, (skb, cap));

	return cap_netlink_recv (skb, cap);
}
#else
int dazuko_security_netlink_recv (struct sk_buff *skb)
{
	RETURN_DAZUKO_LSM_CALL(netlink_recv, (skb));

	return cap_netlink_recv (skb);
}
#endif
#endif


int dazuko_security_unix_stream_connect(struct socket * sock, struct socket * other, struct sock * newsk)
{
#ifdef CONFIG_SECURITY_NETWORK
	RETURN_DAZUKO_LSM_CALL(unix_stream_connect, (sock, other, newsk));
#endif

	return 0;
}


int dazuko_security_unix_may_send(struct socket * sock, struct socket * other)
{
#ifdef CONFIG_SECURITY_NETWORK
	RETURN_DAZUKO_LSM_CALL(unix_may_send, (sock, other));
#endif

	return 0;
}

#if defined(LSM_security_socket_create_2_6_6)
int dazuko_security_socket_create (int family, int type, int protocol, int kern)
{
#ifdef CONFIG_SECURITY_NETWORK
	RETURN_DAZUKO_LSM_CALL(socket_create, (family, type, protocol, kern));
#endif

	return 0;
}
#else
int dazuko_security_socket_create (int family, int type, int protocol)
{
#ifdef CONFIG_SECURITY_NETWORK
	RETURN_DAZUKO_LSM_CALL(socket_create, (family, type, protocol));
#endif

	return 0;
}
#endif

#if defined(LSM_security_socket_post_create_2_6_19)
int dazuko_security_socket_post_create (struct socket * sock, int family, int type, int protocol, int kern)
{
#ifdef CONFIG_SECURITY_NETWORK
	RETURN_DAZUKO_LSM_CALL(socket_post_create, (sock, family, type, protocol, kern));
#endif

	return 0;
}
#elif defined(LSM_security_socket_post_create_2_6_6)
void dazuko_security_socket_post_create(struct socket * sock, int family, int type, int protocol, int kern)
{
#ifdef CONFIG_SECURITY_NETWORK
	VOID_DAZUKO_LSM_CALL(socket_post_create, (sock, family, type, protocol, kern));
#endif
}
#else
void dazuko_security_socket_post_create(struct socket * sock, int family, int type, int protocol)
{
#ifdef CONFIG_SECURITY_NETWORK
	VOID_DAZUKO_LSM_CALL(socket_post_create, (sock, family, type, protocol));
#endif
}
#endif

int dazuko_security_socket_bind(struct socket * sock, struct sockaddr * address, int addrlen)
{
#ifdef CONFIG_SECURITY_NETWORK
	RETURN_DAZUKO_LSM_CALL(socket_bind, (sock, address, addrlen));
#endif

	return 0;
}

int dazuko_security_socket_connect(struct socket * sock, struct sockaddr * address, int addrlen)
{
#ifdef CONFIG_SECURITY_NETWORK
	RETURN_DAZUKO_LSM_CALL(socket_connect, (sock, address, addrlen));
#endif

	return 0;
}

int dazuko_security_socket_listen(struct socket * sock, int backlog)
{
#ifdef CONFIG_SECURITY_NETWORK
	RETURN_DAZUKO_LSM_CALL(socket_listen, (sock, backlog));
#endif

	return 0;
}

int dazuko_security_socket_accept(struct socket * sock, struct socket * newsock)
{
#ifdef CONFIG_SECURITY_NETWORK
	RETURN_DAZUKO_LSM_CALL(socket_accept, (sock, newsock));
#endif

	return 0;
}

void dazuko_security_socket_post_accept(struct socket * sock, struct socket * newsock)
{
#ifdef CONFIG_SECURITY_NETWORK
	VOID_DAZUKO_LSM_CALL(socket_post_accept, (sock, newsock));
#endif
}

int dazuko_security_socket_sendmsg(struct socket * sock, struct msghdr * msg, int size)
{
#ifdef CONFIG_SECURITY_NETWORK
	RETURN_DAZUKO_LSM_CALL(socket_sendmsg, (sock, msg, size));
#endif

	return 0;
}

int dazuko_security_socket_recvmsg(struct socket * sock, struct msghdr * msg, int size, int flags)
{
#ifdef CONFIG_SECURITY_NETWORK
	RETURN_DAZUKO_LSM_CALL(socket_recvmsg, (sock, msg, size, flags));
#endif

	return 0;
}

int dazuko_security_socket_getsockname(struct socket * sock)
{
#ifdef CONFIG_SECURITY_NETWORK
	RETURN_DAZUKO_LSM_CALL(socket_getsockname, (sock));
#endif

	return 0;
}

int dazuko_security_socket_getpeername(struct socket * sock)
{
#ifdef CONFIG_SECURITY_NETWORK
	RETURN_DAZUKO_LSM_CALL(socket_getpeername, (sock));
#endif

	return 0;
}

int dazuko_security_socket_getsockopt(struct socket * sock, int level, int optname)
{
#ifdef CONFIG_SECURITY_NETWORK
	RETURN_DAZUKO_LSM_CALL(socket_getsockopt, (sock, level, optname));
#endif

	return 0;
}

int dazuko_security_socket_setsockopt(struct socket * sock, int level, int optname)
{
#ifdef CONFIG_SECURITY_NETWORK
	RETURN_DAZUKO_LSM_CALL(socket_setsockopt, (sock, level, optname));
#endif

	return 0;
}

int dazuko_security_socket_shutdown(struct socket * sock, int how)
{
#ifdef CONFIG_SECURITY_NETWORK
	RETURN_DAZUKO_LSM_CALL(socket_shutdown, (sock, how));
#endif

	return 0;
}

int dazuko_security_socket_sock_rcv_skb (struct sock * sk, struct sk_buff * skb)
{
#ifdef CONFIG_SECURITY_NETWORK
	RETURN_DAZUKO_LSM_CALL(socket_sock_rcv_skb, (sk, skb));
#endif

	return 0;
}

#if defined(LSM_security_socket_getpeersec_stream_2_6_17)
int dazuko_security_socket_getpeersec_stream(struct socket *sock, char __user *optval, int __user *optlen, unsigned len)
{
#ifdef CONFIG_SECURITY_NETWORK
	RETURN_DAZUKO_LSM_CALL(socket_getpeersec_stream, (sock, optval, optlen, len));
#endif

	return -ENOPROTOOPT;
}
#endif

#if defined(LSM_security_socket_getpeersec_dgram_2_6_19)
int dazuko_security_socket_getpeersec_dgram (struct socket *sock, struct sk_buff *skb, u32 *secid)
{
#ifdef CONFIG_SECURITY_NETWORK
	RETURN_DAZUKO_LSM_CALL(socket_getpeersec_dgram, (sock, skb, secid));
#endif

	return -ENOPROTOOPT;
}
#elif defined(LSM_security_socket_getpeersec_dgram_2_6_17)
int dazuko_security_socket_getpeersec_dgram(struct sk_buff *skb, char **secdata, u32 *seclen)
{
#ifdef CONFIG_SECURITY_NETWORK
	RETURN_DAZUKO_LSM_CALL(socket_getpeersec_dgram, (skb, secdata, seclen));
#endif

	return -ENOPROTOOPT;
}
#endif

#if defined(LSM_security_socket_getpeersec_2_6_2)
int dazuko_security_socket_getpeersec(struct socket *sock, char __user *optval, int __user *optlen, unsigned len)
{
#ifdef CONFIG_SECURITY_NETWORK
	RETURN_DAZUKO_LSM_CALL(socket_getpeersec, (sock, optval, optlen, len));
#endif

	return -ENOPROTOOPT;
}
#endif

#if defined(LSM_security_sk_alloc_security_2_6_15)
int dazuko_security_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
{
#ifdef CONFIG_SECURITY_NETWORK
	RETURN_DAZUKO_LSM_CALL(sk_alloc_security, (sk, family, priority));
#endif

	return 0;
}
#elif defined(LSM_security_sk_alloc_security_2_6_14)
int dazuko_security_sk_alloc_security(struct sock *sk, int family, unsigned int __nocast priority)
{
#ifdef CONFIG_SECURITY_NETWORK
	RETURN_DAZUKO_LSM_CALL(sk_alloc_security, (sk, family, priority));
#endif

	return 0;
}
#elif defined(LSM_security_sk_alloc_security_2_6_2)
int dazuko_security_sk_alloc_security(struct sock *sk, int family, int priority)
{
#ifdef CONFIG_SECURITY_NETWORK
	RETURN_DAZUKO_LSM_CALL(sk_alloc_security, (sk, family, priority));
#endif
	return 0;
}
#endif

#if defined(LSM_security_sk_free_security_2_6_2)
void dazuko_security_sk_free_security(struct sock *sk)
{
#ifdef CONFIG_SECURITY_NETWORK
	VOID_DAZUKO_LSM_CALL(sk_free_security, (sk));
#endif
}
#endif

#if defined(LSM_security_sk_getsid_2_6_17)
unsigned int dazuko_security_sk_getsid(struct sock *sk, struct flowi *fl, u8 dir)
{
#ifdef CONFIG_SECURITY_NETWORK
	RETURN_DAZUKO_LSM_CALL(sk_getsid, (sk, fl, dir));
#endif

	return 0;
}
#endif

#if defined(LSM_security_sk_clone_security_2_6_19)
void dazuko_security_sk_clone_security (const struct sock *sk, struct sock *newsk)
{
#ifdef CONFIG_SECURITY_NETWORK
	VOID_DAZUKO_LSM_CALL(sk_clone_security, (sk, newsk));
#endif
}
#endif

#if defined(LSM_security_sk_getsecid_2_6_19)
void dazuko_security_sk_getsecid (struct sock *sk, u32 *secid)
{
	/* XXX: this is called security_sk_classify_flow() in security.h ?? */
#ifdef CONFIG_SECURITY_NETWORK
	VOID_DAZUKO_LSM_CALL(sk_getsecid, (sk, secid));
#endif
}
#endif

#if defined(LSM_security_sock_graft_2_6_19)
void dazuko_security_sock_graft(struct sock* sk, struct socket *parent)
{
#ifdef CONFIG_SECURITY_NETWORK
	VOID_DAZUKO_LSM_CALL(sock_graft, (sk, parent));
#endif
}
#endif

#if defined(LSM_security_inet_conn_request_2_6_19)
int dazuko_security_inet_conn_request(struct sock *sk, struct sk_buff *skb, struct request_sock *req)
{
#ifdef CONFIG_SECURITY_NETWORK
	RETURN_DAZUKO_LSM_CALL(inet_conn_request, (sk, skb, req));
#endif

	return 0;
}
#endif

#if defined(LSM_security_inet_csk_clone_2_6_19)
void dazuko_security_inet_csk_clone(struct sock *newsk, const struct request_sock *req)
{
#ifdef CONFIG_SECURITY_NETWORK
	VOID_DAZUKO_LSM_CALL(inet_csk_clone, (newsk, req));
#endif
}
#endif

#if defined(LSM_security_inet_conn_established_2_6_20)
void dazuko_security_inet_conn_established(struct sock *sk, struct sk_buff *skb)
{
#ifdef CONFIG_SECURITY_NETWORK
	VOID_DAZUKO_LSM_CALL(inet_conn_established, (sk, skb));
#endif
}
#endif

#if defined(LSM_security_req_classify_flow_2_6_19)
void dazuko_security_req_classify_flow(const struct request_sock *req, struct flowi *fl)
{
#ifdef CONFIG_SECURITY_NETWORK
	VOID_DAZUKO_LSM_CALL(req_classify_flow, (req, fl));
#endif
}
#endif

#ifdef CONFIG_SECURITY_NETWORK_XFRM

#if defined(LSM_security_xfrm_policy_alloc_2_6_19)
int dazuko_security_xfrm_policy_alloc (struct xfrm_policy *xp, struct xfrm_user_sec_ctx *sec_ctx, struct sock *sk)
{
	RETURN_DAZUKO_LSM_CALL(xfrm_policy_alloc_security, (xp, sec_ctx, NULL));

	return 0;
}
#elif defined(LSM_security_xfrm_policy_alloc_2_6_16)
int dazuko_security_xfrm_policy_alloc(struct xfrm_policy *xp, struct xfrm_user_sec_ctx *sec_ctx)
{
	RETURN_DAZUKO_LSM_CALL(xfrm_policy_alloc_security, (xp, sec_ctx));

	return 0;
}
#endif

#if defined(LSM_security_xfrm_policy_clone_2_6_16)
int dazuko_security_xfrm_policy_clone(struct xfrm_policy *old, struct xfrm_policy *new)
{
	RETURN_DAZUKO_LSM_CALL(xfrm_policy_clone_security, (old, new));
	
	return 0;
}
#endif

#if defined(LSM_security_xfrm_policy_free_2_6_16)
void dazuko_security_xfrm_policy_free(struct xfrm_policy *xp)
{
	VOID_DAZUKO_LSM_CALL(xfrm_policy_free_security, (xp));
}
#endif

#if defined(LSM_security_xfrm_policy_delete_2_6_19)
int dazuko_security_xfrm_policy_delete (struct xfrm_policy *xp)
{
	RETURN_DAZUKO_LSM_CALL(xfrm_policy_delete_security, (xp));
	
	return 0;
}
#endif

#if defined(LSM_security_xfrm_state_alloc_2_6_20)
int dazuko_security_xfrm_state_alloc (struct xfrm_state *x, struct xfrm_user_sec_ctx *sec_ctx, u32 secid)
{
	RETURN_DAZUKO_LSM_CALL(xfrm_state_alloc_security, (x, sec_ctx, 0));

	return 0;
}
#elif defined(LSM_security_xfrm_state_alloc_2_6_19)
int dazuko_security_xfrm_state_alloc (struct xfrm_state *x, struct xfrm_user_sec_ctx *sec_ctx, struct xfrm_sec_ctx *polsec, u32 secid)
{
	RETURN_DAZUKO_LSM_CALL(xfrm_state_alloc_security, (x, sec_ctx, NULL, 0));

	return 0;
}
#elif defined(LSM_security_xfrm_state_alloc_2_6_16)
int dazuko_security_xfrm_state_alloc(struct xfrm_state *x, struct xfrm_user_sec_ctx *sec_ctx)
{
	RETURN_DAZUKO_LSM_CALL(xfrm_state_alloc_security, (x, sec_ctx));

	return 0;
}
#endif

#if defined(LSM_security_xfrm_state_free_2_6_16)
void dazuko_security_xfrm_state_free(struct xfrm_state *x)
{
	VOID_DAZUKO_LSM_CALL(xfrm_state_free_security, (x));
}
#endif

#if defined(LSM_security_xfrm_state_delete_2_6_19)
int dazuko_security_xfrm_state_delete (struct xfrm_state *x)
{
	RETURN_DAZUKO_LSM_CALL(xfrm_state_delete_security, (x));

	return 0;
}
#endif

#if defined(LSM_security_xfrm_policy_lookup_2_6_19)
int dazuko_security_xfrm_policy_lookup(struct xfrm_policy *xp, u32 fl_secid, u8 dir)
{
	RETURN_DAZUKO_LSM_CALL(xfrm_policy_lookup, (xp, fl_secid, dir));

	return 0;
}
#elif defined(LSM_security_xfrm_policy_lookup_2_6_16)
int dazuko_security_xfrm_policy_lookup(struct xfrm_policy *xp, u32 sk_sid, u8 dir)
{
	RETURN_DAZUKO_LSM_CALL(xfrm_policy_lookup, (xp, sk_sid, dir));

	return 0;
}
#endif

#if defined(LSM_security_xfrm_state_pol_flow_match_2_6_19)
int dazuko_security_xfrm_state_pol_flow_match(struct xfrm_state *x, struct xfrm_policy *xp, struct flowi *fl)
{
	RETURN_DAZUKO_LSM_CALL(xfrm_state_pol_flow_match, (x, xp, fl));

	return 1;
}
#endif

#if defined(LSM_security_xfrm_flow_state_match_2_6_19)
int dazuko_security_xfrm_flow_state_match(struct flowi *fl, struct xfrm_state *xfrm, struct xfrm_policy *xp)
{
	RETURN_DAZUKO_LSM_CALL(xfrm_flow_state_match, (fl, xfrm, xp));

	return 1;
}
#endif

#if defined(LSM_security_xfrm_decode_session_2_6_19)
int dazuko_security_xfrm_decode_session(struct sk_buff *skb, u32 *secid, int ckall)
{
	RETURN_DAZUKO_LSM_CALL(xfrm_decode_session, (skb, secid, 1));

	return 0;
}
#endif

#endif

#ifdef CONFIG_KEYS

#if defined(LSM_struct_key_alloc_2_6_19)
int dazuko_security_key_alloc(struct key *key, struct task_struct *tsk, unsigned long flags)
{
	RETURN_DAZUKO_LSM_CALL(key_alloc, (key, tsk, flags));

	return 0;
}
#elif defined(LSM_struct_key_alloc_2_6_15)
int dazuko_security_key_alloc(struct key *key)
{
	RETURN_DAZUKO_LSM_CALL(key_alloc, (key));

	return 0;
}
#endif

#if defined(LSM_struct_key_free_2_6_15)
void dazuko_security_key_free(struct key *key)
{
	VOID_DAZUKO_LSM_CALL(key_free, (key));
}
#endif

#if defined(LSM_security_key_permission_2_6_15)
int dazuko_security_key_permission(key_ref_t key_ref, struct task_struct *context, key_perm_t perm)
{
	RETURN_DAZUKO_LSM_CALL(key_permission, (key_ref, context, perm));

	return 0;
}
#endif

#endif


#ifdef NO_CAPABILITIES
int lsm_capability_compare(struct security_operations *ops1, struct security_operations *ops2)
{
	if (ops1->ptrace != ops2->ptrace
		|| ops1->capget != ops2->capget
		|| ops1->capset_check != ops2->capset_check
		|| ops1->capset_set != ops2->capset_set
		|| ops1->capable != ops2->capable
		|| ops1->syslog != ops2->syslog
#if defined(LSM_security_settime_2_6_10)
		|| ops1->settime != ops2->settime
#endif
		|| ops1->vm_enough_memory != ops2->vm_enough_memory
#if defined(LSM_security_bprm_apply_creds_2_6_6) || defined(LSM_security_bprm_apply_creds_2_6_6_mandrake)
		|| ops1->bprm_apply_creds != ops2->bprm_apply_creds
#else
		|| ops1->bprm_compute_creds != ops2->bprm_compute_creds
#endif
		|| ops1->bprm_set_security != ops2->bprm_set_security
		|| ops1->bprm_secureexec != ops2->bprm_secureexec
		|| ops1->inode_setxattr != ops2->inode_setxattr
		|| ops1->inode_removexattr != ops2->inode_removexattr
		|| ops1->task_post_setuid != ops2->task_post_setuid
		|| ops1->task_reparent_to_init != ops2->task_reparent_to_init
		|| ops1->netlink_send != ops2->netlink_send
		|| ops1->netlink_recv != ops2->netlink_recv)
	{
		/* capability hooks are not available */

		return -1;
	}

	return 0;
}
#endif

