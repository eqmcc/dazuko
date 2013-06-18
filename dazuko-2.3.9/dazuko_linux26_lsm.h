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

#ifndef DAZUKO_LINUX26_SECURITY_OPS_H
#define DAZUKO_LINUX26_SECURITY_OPS_H

#include <linux/module.h>
#include <linux/version.h>
#include <linux/security.h>
#include "dazuko_linux26_lsm_def.h"

int dazuko_register_security(const char *name, struct security_operations *ops);
int dazuko_unregister_security(const char *name, struct security_operations *ops);

int dazuko_security_register_security (const char *name, struct security_operations *ops);

int dazuko_security_unregister_security (const char *name, struct security_operations *ops);

#ifndef NO_CAPABILITIES
int dazuko_security_ptrace (struct task_struct *parent, struct task_struct * child);

int dazuko_security_capget (struct task_struct *target, kernel_cap_t *effective, kernel_cap_t *inheritable, kernel_cap_t *permitted);

int dazuko_security_capset_check (struct task_struct *target, kernel_cap_t *effective, kernel_cap_t *inheritable, kernel_cap_t *permitted);

void dazuko_security_capset_set (struct task_struct *target, kernel_cap_t *effective, kernel_cap_t *inheritable, kernel_cap_t *permitted);

int dazuko_security_capable(struct task_struct * tsk, int cap);

int dazuko_security_syslog(int type);

#if defined(LSM_security_settime_2_6_10)
int dazuko_security_settime(struct timespec *ts, struct timezone *tz);
#endif

#if defined(LSM_security_vm_enough_memory_2_6_23)
int dazuko_security_vm_enough_memory(struct mm_struct *mm, long pages);
#else
int dazuko_security_vm_enough_memory(long pages);
#endif

#if defined(LSM_security_bprm_apply_creds_2_6_6)
void dazuko_security_bprm_apply_creds (struct linux_binprm *bprm, int unsafe);
#elif defined(LSM_security_bprm_apply_creds_2_6_6_mandrake)
void dazuko_security_bprm_apply_creds (struct linux_binprm *bprm);
#else
void dazuko_security_bprm_compute_creds (struct linux_binprm *bprm);
#endif

int dazuko_security_bprm_set_security (struct linux_binprm *bprm);

int dazuko_security_bprm_secureexec (struct linux_binprm *bprm);

#if defined(LSM_security_inode_setxattr_2_6_21)
int dazuko_security_inode_setxattr (struct dentry *dentry, struct vfsmount *mnt, char *name, void *value, size_t size, int flags, struct file *file);
#else
int dazuko_security_inode_setxattr (struct dentry *dentry, char *name, void *value, size_t size, int flags);
#endif

#if defined(LSM_security_inode_removexattr_2_6_21)
int dazuko_security_inode_removexattr (struct dentry *dentry, struct vfsmount *mnt, char *name, struct file *file);
#else
int dazuko_security_inode_removexattr (struct dentry *dentry, char *name);
#endif

#if defined(LSM_security_inode_xattr_getsuffix_2_6_17)
const char * dazuko_security_inode_xattr_getsuffix (void);
#endif

int dazuko_security_task_post_setuid (uid_t old_ruid, uid_t old_euid, uid_t old_suid, int flags);

void dazuko_security_task_reparent_to_init (struct task_struct *p);

#if defined(LSM_security_netlink_send_2_6_8)
int dazuko_security_netlink_send (struct sock *sk, struct sk_buff *skb);
#else
int dazuko_security_netlink_send (struct sk_buff *skb);
#endif

#if defined(LSM_security_netlink_recv_2_6_18)
int dazuko_security_netlink_recv (struct sk_buff *skb, int cap);
#else
int dazuko_security_netlink_recv (struct sk_buff *skb);
#endif
#endif /* NO_CAPABILITIES */

int dazuko_security_acct (struct file *file);

#if defined(LSM_security_sysctl_2_6_10)
int dazuko_security_sysctl(struct ctl_table * table, int op);
#else
int dazuko_security_sysctl(ctl_table * table, int op);
#endif

int dazuko_security_quotactl (int cmds, int type, int id, struct super_block * sb);

#if defined(LSM_security_quota_on_2_6_11)
int dazuko_security_quota_on (struct dentry * dentry);
#else
int dazuko_security_quota_on (struct file * file);
#endif

int dazuko_security_bprm_alloc_security (struct linux_binprm *bprm);

void dazuko_security_bprm_free_security (struct linux_binprm *bprm);

#if defined(LSM_security_bprm_post_apply_creds_2_6_11)
void dazuko_security_bprm_post_apply_creds (struct linux_binprm * bprm);
#endif

int dazuko_security_bprm_check_security (struct linux_binprm *bprm);

int dazuko_security_sb_alloc_security (struct super_block *sb);

void dazuko_security_sb_free_security (struct super_block *sb);

#if defined(LSM_security_sb_copy_data_2_6_5)
int dazuko_security_sb_copy_data (struct file_system_type *type, void *orig, void *copy);
#elif defined(LSM_security_sb_copy_data_2_6_3)
int dazuko_security_sb_copy_data (const char *fstype, void *orig, void *copy);
#endif

#if defined(LSM_security_sb_kern_mount_2_6_3)
int dazuko_security_sb_kern_mount (struct super_block *sb, void *data);
#else
int dazuko_security_sb_kern_mount (struct super_block *sb);
#endif

#if defined(LSM_security_sb_statfs_2_6_18)
int dazuko_security_sb_statfs (struct dentry *dentry);
#else
int dazuko_security_sb_statfs (struct super_block *sb);
#endif

int dazuko_security_sb_mount (char *dev_name, struct nameidata *nd, char *type, unsigned long flags, void *data);

int dazuko_security_sb_check_sb (struct vfsmount *mnt, struct nameidata *nd);

int dazuko_security_sb_umount (struct vfsmount *mnt, int flags);

void dazuko_security_sb_umount_close (struct vfsmount *mnt);

void dazuko_security_sb_umount_busy (struct vfsmount *mnt);

void dazuko_security_sb_post_remount (struct vfsmount *mnt, unsigned long flags, void *data);

void dazuko_security_sb_post_mountroot (void);

void dazuko_security_sb_post_addmount (struct vfsmount *mnt, struct nameidata *mountpoint_nd);

int dazuko_security_sb_pivotroot (struct nameidata *old_nd, struct nameidata *new_nd);

void dazuko_security_sb_post_pivotroot (struct nameidata *old_nd, struct nameidata *new_nd);

int dazuko_security_inode_alloc_security (struct inode *inode);

void dazuko_security_inode_free_security (struct inode *inode);

#if defined(LSM_security_inode_init_security_2_6_14)
int dazuko_security_inode_init_security (struct inode *inode, struct inode *dir, char **name, void **value, size_t *len);
#endif

#if defined(LSM_security_inode_create_2_6_21)
int dazuko_security_inode_create (struct inode *dir, struct dentry *dentry, struct vfsmount *mnt, int mode);
#else
int dazuko_security_inode_create (struct inode *dir, struct dentry *dentry, int mode);
#endif

#if defined(LSM_security_inode_post_create_2_6_14)
void dazuko_security_inode_post_create (struct inode *dir, struct dentry *dentry, int mode);
#endif

#if defined(LSM_security_inode_link_2_6_21)
int dazuko_security_inode_link (struct dentry *old_dentry, struct vfsmount *old_mnt, struct inode *dir, struct dentry *new_dentry, struct vfsmount *new_mnt);
#else
int dazuko_security_inode_link (struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry);
#endif

#if defined(LSM_security_inode_post_link_2_6_14)
void dazuko_security_inode_post_link (struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry);
#endif

#if defined(LSM_security_inode_unlink_2_6_21)
int dazuko_security_inode_unlink (struct inode *dir, struct dentry *dentry, struct vfsmount *mnt);
#else
int dazuko_security_inode_unlink (struct inode *dir, struct dentry *dentry);
#endif

#if defined(LSM_security_inode_symlink_2_6_21)
int dazuko_security_inode_symlink (struct inode *dir, struct dentry *dentry, struct vfsmount *mnt, const char *old_name);
#else
int dazuko_security_inode_symlink (struct inode *dir, struct dentry *dentry, const char *old_name);
#endif

#if defined(LSM_security_inode_post_symlink_2_6_14)
void dazuko_security_inode_post_symlink (struct inode *dir, struct dentry *dentry, const char *old_name);
#endif

#if defined(LSM_security_inode_mkdir_2_6_21)
int dazuko_security_inode_mkdir (struct inode *dir, struct dentry *dentry, struct vfsmount *mnt, int mode);
#else
int dazuko_security_inode_mkdir (struct inode *dir, struct dentry *dentry, int mode);
#endif

#if defined(LSM_security_inode_post_mkdir_2_6_14)
void dazuko_security_inode_post_mkdir (struct inode *dir, struct dentry *dentry, int mode);
#endif

#if defined(LSM_security_inode_rmdir_2_6_21)
int dazuko_security_inode_rmdir (struct inode *dir, struct dentry *dentry, struct vfsmount *mnt);
#else
int dazuko_security_inode_rmdir (struct inode *dir, struct dentry *dentry);
#endif

#if defined(LSM_security_inode_mknod_2_6_21)
int dazuko_security_inode_mknod (struct inode *dir, struct dentry *dentry, struct vfsmount *mnt, int mode, dev_t dev);
#else
int dazuko_security_inode_mknod (struct inode *dir, struct dentry *dentry, int mode, dev_t dev);
#endif

#if defined(LSM_security_inode_post_mknod_2_6_14)
void dazuko_security_inode_post_mknod (struct inode *dir, struct dentry *dentry, int mode, dev_t dev);
#endif

#if defined(LSM_security_inode_rename_2_6_21)
int dazuko_security_inode_rename (struct inode *old_dir, struct dentry *old_dentry, struct vfsmount *old_mnt, struct inode *new_dir, struct dentry *new_dentry, struct vfsmount *new_mnt);
#else
int dazuko_security_inode_rename (struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry);
#endif

#if defined(LSM_security_inode_post_rename_2_6_14)
void dazuko_security_inode_post_rename (struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry);
#endif

#if defined(LSM_security_inode_readlink_2_6_21)
int dazuko_security_inode_readlink (struct dentry *dentry, struct vfsmount *mnt);
#else
int dazuko_security_inode_readlink (struct dentry *dentry);
#endif

int dazuko_security_inode_follow_link (struct dentry *dentry, struct nameidata *nd);

int dazuko_security_inode_permission (struct inode *inode, int mask, struct nameidata *nd);

#if defined(LSM_security_inode_setattr_2_6_21)
int dazuko_security_inode_setattr (struct dentry *dentry, struct vfsmount *mnt, struct iattr *attr);
#else
int dazuko_security_inode_setattr (struct dentry *dentry, struct iattr *attr);
#endif

int dazuko_security_inode_getattr (struct vfsmount *mnt, struct dentry *dentry);

void dazuko_security_inode_delete (struct inode *inode);

#if defined(LSM_security_inode_post_setxattr_2_6_21)
void dazuko_security_inode_post_setxattr (struct dentry *dentry, struct vfsmount *mnt, char *name, void *value, size_t size, int flags);
#else
void dazuko_security_inode_post_setxattr (struct dentry *dentry, char *name, void *value, size_t size, int flags);
#endif

#if defined(LSM_security_inode_getxattr_2_6_21)
int dazuko_security_inode_getxattr (struct dentry *dentry, struct vfsmount *mnt, char *name, struct file *file);
#else
int dazuko_security_inode_getxattr (struct dentry *dentry, char *name);
#endif

#if defined(LSM_security_inode_listxattr_2_6_21)
int dazuko_security_inode_listxattr (struct dentry *dentry, struct vfsmount *mnt, struct file *file);
#else
int dazuko_security_inode_listxattr (struct dentry *dentry);
#endif

#if defined(LSM_security_inode_getsecurity_2_6_10)
int dazuko_security_inode_getsecurity(struct inode *inode, const char *name, void *buffer, size_t size);
#elif defined(LSM_security_inode_getsecurity_2_6_17)
int dazuko_security_inode_getsecurity(const struct inode *inode, const char *name, void *buffer, size_t size, int err);
#elif defined(LSM_security_inode_getsecurity_2_6_14)
int dazuko_security_inode_getsecurity(struct inode *inode, const char *name, void *buffer, size_t size, int err);
#else
int dazuko_security_inode_getsecurity(struct dentry *dentry, const char *name, void *buffer, size_t size);
#endif

#if defined(LSM_security_inode_setsecurity_2_6_10)
int dazuko_security_inode_setsecurity(struct inode *inode, const char *name, const void *value, size_t size, int flags);
#else
int dazuko_security_inode_setsecurity(struct dentry *dentry, const char *name, const void *value, size_t size, int flags) ;
#endif

#if defined(LSM_security_inode_listsecurity_2_6_10)
int dazuko_security_inode_listsecurity(struct inode *inode, char *buffer, size_t buffer_size);
#else
int dazuko_security_inode_listsecurity(struct dentry *dentry, char *buffer);
#endif

int dazuko_security_file_permission (struct file *file, int mask);

int dazuko_security_file_alloc_security (struct file *file);

void dazuko_security_file_free_security (struct file *file);

int dazuko_security_file_ioctl (struct file *file, unsigned int cmd, unsigned long arg);

#if defined(LSM_security_file_mmap_2_6_23)
int dazuko_security_file_mmap (struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags, unsigned long addr, unsigned long addr_only);
#elif defined(LSM_security_file_mmap_2_6_12)
int dazuko_security_file_mmap (struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags);
#else
int dazuko_security_file_mmap (struct file *file, unsigned long prot, unsigned long flags);
#endif

#if defined(LSM_security_file_mprotect_2_6_12)
int dazuko_security_file_mprotect (struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot);
#else
int dazuko_security_file_mprotect (struct vm_area_struct *vma, unsigned long prot);
#endif

int dazuko_security_file_lock (struct file *file, unsigned int cmd);

int dazuko_security_file_fcntl (struct file *file, unsigned int cmd, unsigned long arg);

int dazuko_security_file_set_fowner (struct file *file);

#if defined(LSM_security_file_send_sigiotask_2_6_10)
int dazuko_security_file_send_sigiotask (struct task_struct * tsk, struct fown_struct * fown, int sig);
#else
int dazuko_security_file_send_sigiotask (struct task_struct * tsk, struct fown_struct * fown, int fd, int reason);
#endif

int dazuko_security_file_receive (struct file *file);

int dazuko_security_task_create (unsigned long clone_flags);

int dazuko_security_task_alloc_security (struct task_struct *p);

void dazuko_security_task_free_security (struct task_struct *p);

int dazuko_security_task_setuid (uid_t id0, uid_t id1, uid_t id2, int flags);

int dazuko_security_task_setgid (gid_t id0, gid_t id1, gid_t id2, int flags);

int dazuko_security_task_setpgid (struct task_struct *p, pid_t pgid);

int dazuko_security_task_getpgid (struct task_struct *p);

int dazuko_security_task_getsid (struct task_struct *p);

#if defined(LSM_security_task_getsecid_2_6_19)
void dazuko_security_task_getsecid (struct task_struct * p, u32 * secid);
#endif

#if defined(LSM_security_task_setioprio_2_6_19)
int dazuko_security_task_setioprio (struct task_struct * p, int ioprio);
#endif

#if defined(LSM_security_task_getioprio_2_6_19)
int dazuko_security_task_getioprio (struct task_struct * p);
#endif

#if defined(LSM_security_task_movememory_2_6_19)
int dazuko_security_task_movememory (struct task_struct * p);
#endif

#if defined(LSM_security_task_setgroups_2_6_4)
int dazuko_security_task_setgroups (struct group_info *group_info);
#else
int dazuko_security_task_setgroups (int gidsetsize, gid_t * grouplist);
#endif

int dazuko_security_task_setnice (struct task_struct *p, int nice);

int dazuko_security_task_setrlimit (unsigned int resource, struct rlimit *new_rlim);

int dazuko_security_task_setscheduler (struct task_struct *p, int policy, struct sched_param *lp);

int dazuko_security_task_getscheduler (struct task_struct *p);

#if defined(LSM_security_task_kill_2_6_18)
int dazuko_security_task_kill (struct task_struct *p, struct siginfo *info, int sig, u32 secid);
#else
int dazuko_security_task_kill (struct task_struct *p, struct siginfo *info, int sig);
#endif

int dazuko_security_task_wait (struct task_struct *p);

int dazuko_security_task_prctl (int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);

void dazuko_security_task_to_inode(struct task_struct *p, struct inode *inode);

int dazuko_security_ipc_permission (struct kern_ipc_perm *ipcp, short flag);

#if defined(LSM_security_ipc_getsecurity_2_6_17)
int dazuko_security_ipc_getsecurity (struct kern_ipc_perm *ipcp, void *buffer, size_t size);
#endif

int dazuko_security_msg_msg_alloc_security (struct msg_msg * msg);

void dazuko_security_msg_msg_free_security (struct msg_msg * msg);

int dazuko_security_msg_queue_alloc_security (struct msg_queue *msq);

void dazuko_security_msg_queue_free_security (struct msg_queue *msq);

int dazuko_security_msg_queue_associate (struct msg_queue * msq, int msqflg);

int dazuko_security_msg_queue_msgctl (struct msg_queue * msq, int cmd);

int dazuko_security_msg_queue_msgsnd (struct msg_queue * msq, struct msg_msg * msg, int msqflg);

int dazuko_security_msg_queue_msgrcv (struct msg_queue * msq, struct msg_msg * msg, struct task_struct * target, long type, int mode);

int dazuko_security_shm_alloc_security (struct shmid_kernel *shp);

void dazuko_security_shm_free_security (struct shmid_kernel *shp);

int dazuko_security_shm_associate (struct shmid_kernel * shp, int shmflg);

int dazuko_security_shm_shmctl (struct shmid_kernel * shp, int cmd);

#if defined(LSM_security_shm_shmat_2_6_7)
int dazuko_security_shm_shmat (struct shmid_kernel * shp, char __user *shmaddr, int shmflg);
#else
int dazuko_security_shm_shmat (struct shmid_kernel * shp, char *shmaddr, int shmflg);
#endif

int dazuko_security_sem_alloc_security (struct sem_array *sma);

void dazuko_security_sem_free_security (struct sem_array *sma);

int dazuko_security_sem_associate (struct sem_array * sma, int semflg);

int dazuko_security_sem_semctl (struct sem_array * sma, int cmd);

int dazuko_security_sem_semop (struct sem_array * sma, struct sembuf * sops, unsigned nsops, int alter);

void dazuko_security_d_instantiate (struct dentry *dentry, struct inode *inode);

#if defined(LSM_security_getprocattr_2_6_21)
int dazuko_security_getprocattr(struct task_struct *p, char *name, char **value);
#else
int dazuko_security_getprocattr(struct task_struct *p, char *name, void *value, size_t size);
#endif

int dazuko_security_setprocattr(struct task_struct *p, char *name, void *value, size_t size);

#if defined(LSM_security_secid_to_secctx_2_6_19)
int dazuko_security_secid_to_secctx(u32 secid, char **secdata, u32 *seclen);
#endif

#if defined(LSM_security_release_secctx_2_6_19)
void dazuko_security_release_secctx(char *secdata, u32 seclen);
#endif

int dazuko_security_unix_stream_connect(struct socket * sock, struct socket * other, struct sock * newsk);

int dazuko_security_unix_may_send(struct socket * sock, struct socket * other);

#if defined(LSM_security_socket_create_2_6_6)
int dazuko_security_socket_create (int family, int type, int protocol, int kern);
#else
int dazuko_security_socket_create (int family, int type, int protocol);
#endif

#if defined(LSM_security_socket_post_create_2_6_19)
int dazuko_security_socket_post_create (struct socket * sock, int family, int type, int protocol, int kern);
#elif defined(LSM_security_socket_post_create_2_6_6)
void dazuko_security_socket_post_create(struct socket * sock, int family, int type, int protocol, int kern);
#else
void dazuko_security_socket_post_create(struct socket * sock, int family, int type, int protocol);
#endif

int dazuko_security_socket_bind(struct socket * sock, struct sockaddr * address, int addrlen);

int dazuko_security_socket_connect(struct socket * sock, struct sockaddr * address, int addrlen);

int dazuko_security_socket_listen(struct socket * sock, int backlog);

int dazuko_security_socket_accept(struct socket * sock, struct socket * newsock);

void dazuko_security_socket_post_accept(struct socket * sock, struct socket * newsock);

int dazuko_security_socket_sendmsg(struct socket * sock, struct msghdr * msg, int size);

int dazuko_security_socket_recvmsg(struct socket * sock, struct msghdr * msg, int size, int flags);

int dazuko_security_socket_getsockname(struct socket * sock);

int dazuko_security_socket_getpeername(struct socket * sock);

int dazuko_security_socket_getsockopt(struct socket * sock, int level, int optname);

int dazuko_security_socket_setsockopt(struct socket * sock, int level, int optname);

int dazuko_security_socket_shutdown(struct socket * sock, int how);

int dazuko_security_socket_sock_rcv_skb (struct sock * sk, struct sk_buff * skb);

#if defined(LSM_security_socket_getpeersec_stream_2_6_17)
int dazuko_security_socket_getpeersec_stream(struct socket *sock, char __user *optval, int __user *optlen, unsigned len);
#endif

#if defined(LSM_security_socket_getpeersec_dgram_2_6_19)
int dazuko_security_socket_getpeersec_dgram (struct socket *sock, struct sk_buff *skb, u32 *secid);
#elif defined(LSM_security_socket_getpeersec_dgram_2_6_17)
int dazuko_security_socket_getpeersec_dgram(struct sk_buff *skb, char **secdata, u32 *seclen);
#endif

#if defined(LSM_security_socket_getpeersec_2_6_2)
int dazuko_security_socket_getpeersec(struct socket *sock, char __user *optval, int __user *optlen, unsigned len);
#endif

#if defined(LSM_security_sk_alloc_security_2_6_15)
int dazuko_security_sk_alloc_security(struct sock *sk, int family, gfp_t priority);
#elif defined(LSM_security_sk_alloc_security_2_6_14)
int dazuko_security_sk_alloc_security(struct sock *sk, int family, unsigned int __nocast priority);
#elif defined(LSM_security_sk_alloc_security_2_6_2)
int dazuko_security_sk_alloc_security(struct sock *sk, int family, int priority);
#endif

#if defined(LSM_security_sk_free_security_2_6_2)
void dazuko_security_sk_free_security(struct sock *sk);
#endif

#if defined(LSM_security_sk_getsid_2_6_17)
unsigned int dazuko_security_sk_getsid(struct sock *sk, struct flowi *fl, u8 dir);
#endif

#if defined(LSM_security_sk_clone_security_2_6_19)
void dazuko_security_sk_clone_security (const struct sock *sk, struct sock *newsk);
#endif

#if defined(LSM_security_sk_getsecid_2_6_19)
void dazuko_security_sk_getsecid (struct sock *sk, u32 *secid);
#endif

#if defined(LSM_security_sock_graft_2_6_19)
void dazuko_security_sock_graft(struct sock* sk, struct socket *parent);
#endif

#if defined(LSM_security_inet_conn_request_2_6_19)
int dazuko_security_inet_conn_request(struct sock *sk, struct sk_buff *skb, struct request_sock *req);
#endif

#if defined(LSM_security_inet_csk_clone_2_6_19)
void dazuko_security_inet_csk_clone(struct sock *newsk, const struct request_sock *req);
#endif

#if defined(LSM_security_inet_conn_established_2_6_20)
void dazuko_security_inet_conn_established(struct sock *sk, struct sk_buff *skb);
#endif

#if defined(LSM_security_req_classify_flow_2_6_19)
void dazuko_security_req_classify_flow(const struct request_sock *req, struct flowi *fl);
#endif

#ifdef CONFIG_KEYS

#if defined(LSM_struct_key_alloc_2_6_19)
int dazuko_security_key_alloc(struct key *key, struct task_struct *tsk, unsigned long flags);
#elif defined(LSM_struct_key_alloc_2_6_15)
int dazuko_security_key_alloc(struct key *key);
#endif

#if defined(LSM_struct_key_free_2_6_15)
void dazuko_security_key_free(struct key *key);
#endif

#if defined(LSM_security_key_permission_2_6_15)
int dazuko_security_key_permission(key_ref_t key_ref, struct task_struct *context, key_perm_t perm);
#endif

#endif

#ifdef CONFIG_SECURITY_NETWORK_XFRM

#if defined(LSM_security_xfrm_policy_alloc_2_6_19)
int dazuko_security_xfrm_policy_alloc (struct xfrm_policy *xp, struct xfrm_user_sec_ctx *sec_ctx, struct sock *sk);
#elif defined(LSM_security_xfrm_policy_alloc_2_6_16)
int dazuko_security_xfrm_policy_alloc(struct xfrm_policy *xp, struct xfrm_user_sec_ctx *sec_ctx);
#endif

#if defined(LSM_security_xfrm_policy_clone_2_6_16)
int dazuko_security_xfrm_policy_clone(struct xfrm_policy *old, struct xfrm_policy *new);
#endif

#if defined(LSM_security_xfrm_policy_free_2_6_16)
void dazuko_security_xfrm_policy_free(struct xfrm_policy *xp);
#endif

#if defined(LSM_security_xfrm_policy_delete_2_6_19)
int dazuko_security_xfrm_policy_delete (struct xfrm_policy *xp);
#endif

#if defined(LSM_security_xfrm_state_alloc_2_6_20)
int dazuko_security_xfrm_state_alloc (struct xfrm_state *x, struct xfrm_user_sec_ctx *sec_ctx, u32 secid);
#elif defined(LSM_security_xfrm_state_alloc_2_6_19)
int dazuko_security_xfrm_state_alloc (struct xfrm_state *x, struct xfrm_user_sec_ctx *sec_ctx, struct xfrm_sec_ctx *polsec, u32 secid);
#elif defined(LSM_security_xfrm_state_alloc_2_6_16)
int dazuko_security_xfrm_state_alloc(struct xfrm_state *x, struct xfrm_user_sec_ctx *sec_ctx);
#endif

#if defined(LSM_security_xfrm_state_free_2_6_16)
void dazuko_security_xfrm_state_free(struct xfrm_state *x);
#endif

#if defined(LSM_security_xfrm_state_delete_2_6_19)
int dazuko_security_xfrm_state_delete (struct xfrm_state *x);
#endif

#if defined(LSM_security_xfrm_policy_lookup_2_6_19)
int dazuko_security_xfrm_policy_lookup(struct xfrm_policy *xp, u32 fl_secid, u8 dir);
#elif defined(LSM_security_xfrm_policy_lookup_2_6_16)
int dazuko_security_xfrm_policy_lookup(struct xfrm_policy *xp, u32 sk_sid, u8 dir);
#endif

#if defined(LSM_security_xfrm_state_pol_flow_match_2_6_19)
int dazuko_security_xfrm_state_pol_flow_match(struct xfrm_state *x, struct xfrm_policy *xp, struct flowi *fl);
#endif

#if defined(LSM_security_xfrm_flow_state_match_2_6_19)
int dazuko_security_xfrm_flow_state_match(struct flowi *fl, struct xfrm_state *xfrm, struct xfrm_policy *xp);
#endif

#if defined(LSM_security_xfrm_decode_session_2_6_19)
int dazuko_security_xfrm_decode_session(struct sk_buff *skb, u32 *secid, int ckall);
#endif

#endif

struct security_operations dazuko_security_ops;
struct security_operations dazuko_security_default_ops;

/* all hooks are registered (to allow proper stacking) */
struct security_operations dazuko_register_security_ops = {
	.register_security = dazuko_register_security,
	.unregister_security = dazuko_unregister_security,

#ifndef NO_CAPABILITIES
	.ptrace = dazuko_security_ptrace,
	.capget = dazuko_security_capget,
	.capset_check = dazuko_security_capset_check,
	.capset_set = dazuko_security_capset_set,
	.capable = dazuko_security_capable,
	.syslog = dazuko_security_syslog,
#if defined(LSM_security_settime_2_6_10)
	.settime = dazuko_security_settime,
#endif
	.vm_enough_memory = dazuko_security_vm_enough_memory,
#if defined(LSM_security_bprm_apply_creds_2_6_6) || defined(LSM_security_bprm_apply_creds_2_6_6_mandrake)
	.bprm_apply_creds = dazuko_security_bprm_apply_creds,
#else
	.bprm_compute_creds = dazuko_security_bprm_compute_creds,
#endif
	.bprm_set_security = dazuko_security_bprm_set_security,
	.bprm_secureexec = dazuko_security_bprm_secureexec,
	.inode_setxattr = dazuko_security_inode_setxattr,
	.inode_removexattr = dazuko_security_inode_removexattr,
#if defined(LSM_security_inode_xattr_getsuffix_2_6_17)
	.inode_xattr_getsuffix = dazuko_security_inode_xattr_getsuffix,
#endif
	.task_post_setuid = dazuko_security_task_post_setuid,
	.task_reparent_to_init = dazuko_security_task_reparent_to_init,
	.netlink_send = dazuko_security_netlink_send,
	.netlink_recv = dazuko_security_netlink_recv,
#endif

	.acct = dazuko_security_acct,
	.sysctl = dazuko_security_sysctl,
	.quotactl = dazuko_security_quotactl,
	.quota_on = dazuko_security_quota_on,
	.bprm_alloc_security = dazuko_security_bprm_alloc_security,
	.bprm_free_security = dazuko_security_bprm_free_security,
#if defined(LSM_security_bprm_post_apply_creds_2_6_11)
	.bprm_post_apply_creds = dazuko_security_bprm_post_apply_creds,
#endif
	.bprm_check_security = dazuko_security_bprm_check_security,
	.sb_alloc_security = dazuko_security_sb_alloc_security,
	.sb_free_security = dazuko_security_sb_free_security,
#if defined(LSM_security_sb_copy_data_2_6_3)
	.sb_copy_data = dazuko_security_sb_copy_data,
#endif
	.sb_kern_mount = dazuko_security_sb_kern_mount,
	.sb_statfs = dazuko_security_sb_statfs,
	.sb_mount = dazuko_security_sb_mount,
	.sb_check_sb = dazuko_security_sb_check_sb,
	.sb_umount = dazuko_security_sb_umount,
	.sb_umount_close = dazuko_security_sb_umount_close,
	.sb_umount_busy = dazuko_security_sb_umount_busy,
	.sb_post_remount = dazuko_security_sb_post_remount,
	.sb_post_mountroot = dazuko_security_sb_post_mountroot,
	.sb_post_addmount = dazuko_security_sb_post_addmount,
	.sb_pivotroot = dazuko_security_sb_pivotroot,
	.sb_post_pivotroot = dazuko_security_sb_post_pivotroot,
	.inode_alloc_security = dazuko_security_inode_alloc_security,
	.inode_free_security = dazuko_security_inode_free_security,
#if defined(LSM_security_inode_init_security_2_6_14)
	.inode_init_security = dazuko_security_inode_init_security,
#endif
	.inode_create = dazuko_security_inode_create,
#if defined(LSM_security_inode_post_create_2_6_14)
	.inode_post_create = dazuko_security_inode_post_create,
#endif
	.inode_link = dazuko_security_inode_link,
#if defined(LSM_security_inode_post_link_2_6_14)
	.inode_post_link = dazuko_security_inode_post_link,
#endif
	.inode_unlink = dazuko_security_inode_unlink,
	.inode_symlink = dazuko_security_inode_symlink,
#if defined(LSM_security_inode_post_symlink_2_6_14)
	.inode_post_symlink = dazuko_security_inode_post_symlink,
#endif
	.inode_mkdir = dazuko_security_inode_mkdir,
#if defined(LSM_security_inode_post_mkdir_2_6_14)
	.inode_post_mkdir = dazuko_security_inode_post_mkdir,
#endif
	.inode_rmdir = dazuko_security_inode_rmdir,
	.inode_mknod = dazuko_security_inode_mknod,
#if defined(LSM_security_inode_post_mknod_2_6_14)
	.inode_post_mknod = dazuko_security_inode_post_mknod,
#endif
	.inode_rename = dazuko_security_inode_rename,
#if defined(LSM_security_inode_post_rename_2_6_14)
	.inode_post_rename = dazuko_security_inode_post_rename,
#endif
	.inode_readlink = dazuko_security_inode_readlink,
	.inode_follow_link = dazuko_security_inode_follow_link,
	.inode_permission = dazuko_security_inode_permission,
	.inode_setattr = dazuko_security_inode_setattr,
	.inode_getattr = dazuko_security_inode_getattr,
	.inode_delete = dazuko_security_inode_delete,
	.inode_post_setxattr = dazuko_security_inode_post_setxattr,
	.inode_getxattr = dazuko_security_inode_getxattr,
	.inode_listxattr = dazuko_security_inode_listxattr,
	.inode_getsecurity = dazuko_security_inode_getsecurity,
	.inode_setsecurity = dazuko_security_inode_setsecurity,
	.inode_listsecurity = dazuko_security_inode_listsecurity,
	.file_permission = dazuko_security_file_permission,
	.file_alloc_security = dazuko_security_file_alloc_security,
	.file_free_security = dazuko_security_file_free_security,
	.file_ioctl = dazuko_security_file_ioctl,
	.file_mmap = dazuko_security_file_mmap,
	.file_mprotect = dazuko_security_file_mprotect,
	.file_lock = dazuko_security_file_lock,
	.file_fcntl = dazuko_security_file_fcntl,
	.file_set_fowner = dazuko_security_file_set_fowner,
	.file_send_sigiotask = dazuko_security_file_send_sigiotask,
	.file_receive = dazuko_security_file_receive,
	.task_create = dazuko_security_task_create,
	.task_alloc_security = dazuko_security_task_alloc_security,
	.task_free_security = dazuko_security_task_free_security,
	.task_setuid = dazuko_security_task_setuid,
	.task_setgid = dazuko_security_task_setgid,
	.task_setpgid = dazuko_security_task_setpgid,
	.task_getpgid = dazuko_security_task_getpgid,
	.task_getsid = dazuko_security_task_getsid,
#if defined(LSM_security_task_getsecid_2_6_19)
	.task_getsecid = dazuko_security_task_getsecid,
#endif
#if defined(LSM_security_task_setioprio_2_6_19)
	.task_setioprio = dazuko_security_task_setioprio,
#endif
#if defined(LSM_security_task_getioprio_2_6_19)
	.task_getioprio = dazuko_security_task_getioprio,
#endif
#if defined(LSM_security_task_movememory_2_6_19)
	.task_movememory = dazuko_security_task_movememory,
#endif
	.task_setgroups = dazuko_security_task_setgroups,
	.task_setnice = dazuko_security_task_setnice,
	.task_setrlimit = dazuko_security_task_setrlimit,
	.task_setscheduler = dazuko_security_task_setscheduler,
	.task_getscheduler = dazuko_security_task_getscheduler,
	.task_kill = dazuko_security_task_kill,
	.task_wait = dazuko_security_task_wait,
	.task_prctl = dazuko_security_task_prctl,
	.task_to_inode = dazuko_security_task_to_inode,
	.ipc_permission = dazuko_security_ipc_permission,
#if defined(LSM_security_ipc_getsecurity_2_6_17)
	.ipc_getsecurity = dazuko_security_ipc_getsecurity,
#endif
	.msg_msg_alloc_security = dazuko_security_msg_msg_alloc_security,
	.msg_msg_free_security = dazuko_security_msg_msg_free_security,
	.msg_queue_alloc_security = dazuko_security_msg_queue_alloc_security,
	.msg_queue_free_security = dazuko_security_msg_queue_free_security,
	.msg_queue_associate = dazuko_security_msg_queue_associate,
	.msg_queue_msgctl = dazuko_security_msg_queue_msgctl,
	.msg_queue_msgsnd = dazuko_security_msg_queue_msgsnd,
	.msg_queue_msgrcv = dazuko_security_msg_queue_msgrcv,
	.shm_alloc_security = dazuko_security_shm_alloc_security,
	.shm_free_security = dazuko_security_shm_free_security,
	.shm_associate = dazuko_security_shm_associate,
	.shm_shmctl = dazuko_security_shm_shmctl,
	.shm_shmat = dazuko_security_shm_shmat,
	.sem_alloc_security = dazuko_security_sem_alloc_security,
	.sem_free_security = dazuko_security_sem_free_security,
	.sem_associate = dazuko_security_sem_associate,
	.sem_semctl = dazuko_security_sem_semctl,
	.sem_semop = dazuko_security_sem_semop,
	.d_instantiate = dazuko_security_d_instantiate,
	.getprocattr = dazuko_security_getprocattr,
	.setprocattr = dazuko_security_setprocattr,
#if defined(LSM_security_secid_to_secctx_2_6_19)
	.secid_to_secctx = dazuko_security_secid_to_secctx,
#endif
#if defined(LSM_security_release_secctx_2_6_19)
	.release_secctx = dazuko_security_release_secctx,
#endif

#ifdef CONFIG_SECURITY_NETWORK
	.unix_stream_connect = dazuko_security_unix_stream_connect,
	.unix_may_send = dazuko_security_unix_may_send,
	.socket_create = dazuko_security_socket_create,
	.socket_post_create = dazuko_security_socket_post_create,
	.socket_bind = dazuko_security_socket_bind,
	.socket_connect = dazuko_security_socket_connect,
	.socket_listen = dazuko_security_socket_listen,
	.socket_accept = dazuko_security_socket_accept,
	.socket_post_accept = dazuko_security_socket_post_accept,
	.socket_sendmsg = dazuko_security_socket_sendmsg,
	.socket_recvmsg = dazuko_security_socket_recvmsg,
	.socket_getsockname = dazuko_security_socket_getsockname,
	.socket_getpeername = dazuko_security_socket_getpeername,
	.socket_getsockopt = dazuko_security_socket_getsockopt,
	.socket_setsockopt = dazuko_security_socket_setsockopt,
	.socket_shutdown = dazuko_security_socket_shutdown,
	.socket_sock_rcv_skb = dazuko_security_socket_sock_rcv_skb,
#if defined(LSM_security_socket_getpeersec_stream_2_6_17)
	.socket_getpeersec_stream = dazuko_security_socket_getpeersec_stream,
#endif
#if defined(LSM_security_socket_getpeersec_dgram_2_6_17)
	.socket_getpeersec_dgram = dazuko_security_socket_getpeersec_dgram,
#endif
#if defined(LSM_security_socket_getpeersec_2_6_2)
	.socket_getpeersec = dazuko_security_socket_getpeersec,
#endif
#if defined(LSM_security_sk_alloc_security_2_6_2)
	.sk_alloc_security = dazuko_security_sk_alloc_security,
#endif
#if defined(LSM_security_sk_alloc_security_2_6_2)
	.sk_free_security = dazuko_security_sk_free_security,
#endif
#if defined(LSM_security_sk_getsid_2_6_17)
	.sk_getsid = dazuko_security_sk_getsid,
#endif
#if defined(LSM_security_sk_clone_security_2_6_19)
	.sk_clone_security = dazuko_security_sk_clone_security,
#endif
#if defined(LSM_security_sk_getsecid_2_6_19)
	.sk_getsecid = dazuko_security_sk_getsecid,
#endif
#if defined(LSM_security_sock_graft_2_6_19)
	.sock_graft = dazuko_security_sock_graft,
#endif
#if defined(LSM_security_inet_conn_request_2_6_19)
	.inet_conn_request = dazuko_security_inet_conn_request,
#endif
#if defined(LSM_security_inet_csk_clone_2_6_19)
	.inet_csk_clone = dazuko_security_inet_csk_clone,
#endif
#if defined(LSM_security_inet_conn_established_2_6_20)
	.inet_conn_established = dazuko_security_inet_conn_established,
#endif
#if defined(LSM_security_req_classify_flow_2_6_19)
	.req_classify_flow = dazuko_security_req_classify_flow,
#endif
#endif

#ifdef CONFIG_SECURITY_NETWORK_XFRM
#if defined(LSM_security_xfrm_policy_alloc_security_2_6_16)
	.xfrm_policy_alloc_security = dazuko_security_xfrm_policy_alloc,
#endif
#if defined(LSM_security_xfrm_policy_clone_security_2_6_16)
	.xfrm_policy_clone_security = dazuko_security_xfrm_policy_clone,
#endif
#if defined(LSM_security_xfrm_policy_free_security_2_6_16)
	.xfrm_policy_free_security = dazuko_security_xfrm_policy_free,
#endif
#if defined(LSM_security_xfrm_state_alloc_security_2_6_16)
	.xfrm_state_alloc_security = dazuko_security_xfrm_state_alloc,
#endif
#if defined(LSM_security_xfrm_state_free_security_2_6_16)
	.xfrm_state_free_security = dazuko_security_xfrm_state_free,
#endif
#if defined(LSM_security_xfrm_policy_lookup_2_6_16)
	.xfrm_policy_lookup = dazuko_security_xfrm_policy_lookup,
#endif
#if defined(LSM_security_xfrm_policy_delete_2_6_19)
	.xfrm_policy_delete_security = dazuko_security_xfrm_policy_delete,
#endif
#if defined(LSM_security_xfrm_state_delete_2_6_19)
	.xfrm_state_delete_security = dazuko_security_xfrm_state_delete,
#endif
#if defined(LSM_security_xfrm_state_pol_flow_match_2_6_19)
	.xfrm_state_pol_flow_match = dazuko_security_xfrm_state_pol_flow_match,
#endif
#if defined(LSM_security_xfrm_flow_state_match_2_6_19)
	.xfrm_flow_state_match = dazuko_security_xfrm_flow_state_match,
#endif
#if defined(LSM_security_xfrm_decode_session_2_6_19)
	.xfrm_decode_session = dazuko_security_xfrm_decode_session,
#endif
#endif

#ifdef CONFIG_KEYS
#if defined(LSM_struct_key_alloc_2_6_15)
	.key_alloc = dazuko_security_key_alloc,
#endif
#if defined(LSM_struct_key_free_2_6_15)
	.key_free = dazuko_security_key_free,
#endif
#if defined(LSM_security_key_permission_2_6_15)
	.key_permission = dazuko_security_key_permission,
#endif

#endif
};

#endif /* DAZUKO_LINUX26_SECURITY_OPS_H */

