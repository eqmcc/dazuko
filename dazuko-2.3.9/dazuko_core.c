/* DazukoXP. Allow cross platform file access control for 3rd-party applications.
   Written by John Ogness <dazukocode@ogness.net>

   Copyright (c) 2002, 2003, 2004, 2005, 2006 H+BEDV Datentechnik GmbH
   Copyright (c) 2006, 2007 Avira GmbH
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

#include "dazuko_platform.h"
#include "dazuko_core.h"
#include "dazuko_version.h"

/* inline code */
#include "dazuko_call.h"

/* binary version stamp */
const char	*DAZUKO_VERSION_STAMP = "\nDazukoVersion=" DAZUKO_VERSION_MAJOR "." DAZUKO_VERSION_MINOR "." DAZUKO_VERSION_REVISION "." DAZUKO_VERSION_RELEASE "\n";

/* version string for display */
const char	*VERSION_STRING = DAZUKO_VERSION_MAJOR "." DAZUKO_VERSION_MINOR "." DAZUKO_VERSION_REVISION
#ifdef DAZUKO_PRERELEASE
"-pre" DAZUKO_VERSION_RELEASE
#endif
;

/* technical version string */
const char	*VERSION_NUMBER = DAZUKO_VERSION_MAJOR "." DAZUKO_VERSION_MINOR "." DAZUKO_VERSION_REVISION "." DAZUKO_VERSION_RELEASE;

#define NUM_SLOT_LISTS	5

#ifndef NUM_SLOTS
#define NUM_SLOTS	25
#endif

#define NUM_EVENTS	7

#define AMC_UNSET	255

/* slot states */
#define	DAZUKO_FREE	0	/* the daemon is not ready */
#define	DAZUKO_READY	1	/* a daemon waits for something to do */
#define	DAZUKO_WAITING	2	/* a request is waiting to be served */
#define	DAZUKO_WORKING	3	/* daemon is currently in action */
#define	DAZUKO_DONE	4	/* daemon response is available */
#define	DAZUKO_BROKEN	5	/* invalid state (interrupt from ready,waiting) */


struct dazuko_path
{
	/* A node in a linked list of paths. Used
	 * for the include and exclude lists. */

	struct dazuko_path *next;
	int		len;
	char		*path;
};

struct daemon_id
{
	int			unique;
	struct xp_daemon_id	*xp_id;
};

#ifdef TRUSTED_APPLICATION_SUPPORT
struct trusted_container
{
	struct xp_daemon_id		*xp_id;
	char				*token;
	int				token_length;
	int				trust_children;
	struct trusted_container	*next;
};
#endif

struct slot_list;

struct slot
{
	/* A representation of a daemon. It holds
	 * all information about the daemon, the
	 * file that is scanned, and the state of
	 * the scanning process. */

	int			id;		
	struct daemon_id	did;		/* identifier for our daemon */
	int			write_mode;
	int			state;
	int			response;
	int			event;
	int			filenamelength;	/* not including terminator */
	char			*filename;
	struct event_properties	event_p;
	struct file_properties	file_p;
	struct xp_mutex		mutex;
	struct slot_list	*slot_list;
	struct xp_queue		wait_daemon_waiting_until_this_slot_not_READY;
	struct xp_queue		wait_kernel_waiting_until_this_slot_not_WAITING_and_not_WORKING;
	struct xp_queue		wait_daemon_waiting_until_this_slot_not_DONE;
	struct dazuko_file_struct	*dfs;
};

struct slot_list
{
	struct xp_atomic		use_count;
	struct slot			slots[NUM_SLOTS];
	struct dazuko_path		*incl_paths;
	struct dazuko_path		*excl_paths;
	char				*reg_name;
	struct xp_rwlock		lock_lists;
	char				access_mask;
#ifdef TRUSTED_APPLICATION_SUPPORT
	struct xp_rwlock		lock_trusted_list;
	struct trusted_container	*trusted_list;
	char				set_trusted_list;
#endif
	struct xp_queue			wait_kernel_waiting_for_any_READY_slot_or_zero_use_count;
};

struct slot_list_container
{
	struct slot_list	*slot_list;
	struct xp_mutex		mutex;
};

struct one_slot_state_not_condition_param
{
	struct slot	*slot;
	int		state;
};

struct two_slot_state_not_condition_param
{
	struct slot	*slot1;
	int		state1;
	struct slot	*slot2;
	int		state2;
};

struct get_ready_slot_condition_param
{
	struct slot		*slot;
	struct slot_list	*slotlist;
};

static int				unique_count = 1;
static struct slot_list_container	slot_lists[NUM_SLOT_LISTS];
static struct xp_atomic			active;
static struct xp_atomic			groupcount;
static struct xp_mutex			mutex_unique_count;
static unsigned char			access_mask_cache[NUM_EVENTS][NUM_SLOT_LISTS];
static struct xp_mutex			mutex_amc;


int dazuko_vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
	char		*target;
	const char	*end;
	int		overflow = 0;
	char		number_buffer[32]; /* 32 should be enough to hold any number, right? */
	const char	*s;

	if (str == NULL || size < 1 || format == NULL)
		return -1;

	target = str;
	end = (target + size) - 1;

#define DAZUKO_VSNPRINTF_PRINTSTRING \
	for ( ; *s ; s++) \
	{ \
		if (target == end) \
		{ \
			overflow = 1; \
			goto dazuko_vsnprintf_out; \
		} \
		*target = *s; \
		target++; \
	}

	for ( ; *format ; format++)
	{
		if (target == end)
		{
			overflow = 1;
			goto dazuko_vsnprintf_out;
		}

		if (*format == '%')
		{
			format++;

			switch (*format)
			{
				case 's': /* %s */
					s = va_arg(ap, char *);
					if (s == NULL)
						s = "(null)";
					DAZUKO_VSNPRINTF_PRINTSTRING
					break;

				case 'd': /* %d */
					sprintf(number_buffer, "%d", va_arg(ap, int));
					s = number_buffer;
					DAZUKO_VSNPRINTF_PRINTSTRING
					break;

				case 'p': /* %p */
					sprintf(number_buffer, "%p", va_arg(ap, void *));
					s = number_buffer;
					DAZUKO_VSNPRINTF_PRINTSTRING
					break;

				case 'c': /* %c */
					*target = va_arg(ap, int);
					target++;
					break;

				case 'l': /* %lu */
					format++;
					if (*format != 'u')
					{
						/* print error message */
						goto dazuko_vsnprintf_out;
					}
					sprintf(number_buffer, "%lu", va_arg(ap, unsigned long));
					s = number_buffer;
					DAZUKO_VSNPRINTF_PRINTSTRING
					break;

				case '0': /* %02x */
					format++;
					if (*format != '2')
					{
						/* print error message */
						goto dazuko_vsnprintf_out;
					}
					format++;
					if (*format != 'x')
					{
						/* print error message */
						goto dazuko_vsnprintf_out;
					}
					sprintf(number_buffer, "%02x", va_arg(ap, int));
					s = number_buffer;
					DAZUKO_VSNPRINTF_PRINTSTRING
					break;

				default:
					/* print error message */
					goto dazuko_vsnprintf_out;
			}
		}
		else
		{
			*target = *format;
			target++;
		}
	}

dazuko_vsnprintf_out:

	*target = 0;

	/* We are returning what we've written. If there was an
	 * overflow, the returned value will match "size" rather
	 * than being less than "size"
	 */

	return ((target - str) + overflow);
}

int dazuko_snprintf(char *str, size_t size, const char *format, ...)
{
	va_list	ap;
	int	ret;

	va_start(ap, format);
	ret = dazuko_vsnprintf(str, size, format, ap);
	va_end(ap);

	return ret;
}

inline void dazuko_bzero(void *p, int len)
{
	/* "zero out" len bytes starting with p */

	char	*ptr = (char *)p;

	while (len--)
		*ptr++ = 0;
}

static inline int dazuko_event2index(unsigned long event)
{
	switch (event)
	{
		case DAZUKO_ON_OPEN:
			return 0;
		case DAZUKO_ON_CLOSE:
			return 1;
		case DAZUKO_ON_EXEC:
			return 2;
		case DAZUKO_ON_CLOSE_MODIFIED:
			return 3;
		case DAZUKO_ON_UNLINK:
			return 4;
		case DAZUKO_ON_RMDIR:
			return 5;
		case DAZUKO_TRUST_REQUEST:
			return 6;
	}

	return -1;
}

static inline unsigned long dazuko_index2event(int index)
{
	switch (index)
	{
		case 0:
			return DAZUKO_ON_OPEN;
		case 1:
			return DAZUKO_ON_CLOSE;
		case 2:
			return DAZUKO_ON_EXEC;
		case 3:
			return DAZUKO_ON_CLOSE_MODIFIED;
		case 4:
			return DAZUKO_ON_UNLINK;
		case 5:
			return DAZUKO_ON_RMDIR;
		case 6:
			return DAZUKO_TRUST_REQUEST;
	}

	return 0;
}

static void dazuko_setup_amc_cache(void)
{
	int			i;
	int			j;
	struct slot_list	*sl;
	unsigned long		event;
	int			index;

/* DOWN */
	call_xp_down(&mutex_amc);

	memset(&access_mask_cache, AMC_UNSET, sizeof(access_mask_cache));

	for (i=0 ; i<NUM_EVENTS ; i++)
	{
		event = dazuko_index2event(i);
		if (event == 0)
			continue;

		index = 0;

		for (j=0 ; j<NUM_SLOT_LISTS ; j++)
		{
/* DOWN */
			call_xp_down(&(slot_lists[j].mutex));

			sl = slot_lists[j].slot_list;

			call_xp_up(&(slot_lists[j].mutex));
/* UP */

			if (sl == NULL)
				continue;

			switch (event)
			{
				case DAZUKO_ON_CLOSE:
					/* this is a special case since ON_CLOSE_MODIFIED
					 * also triggers ON_CLOSE events */

					if (((DAZUKO_ON_CLOSE | DAZUKO_ON_CLOSE_MODIFIED) & (sl->access_mask)) == 0)
						continue;
					break;
				default:
					if ((event & (sl->access_mask)) == 0)
						continue;
					break;
			}

			/* if we made it this far, then the
			 * event is in the access mask */

			access_mask_cache[i][index] = j;
			index++;
		}
	}

	call_xp_up(&mutex_amc);
/* UP */
}


static inline int dazuko_get_new_unique(void)
{
	int	unique;

/* DOWN */
	call_xp_down(&mutex_unique_count);

	unique = unique_count;
	unique_count++;

	call_xp_up(&mutex_unique_count);
/* UP */

	return unique;
}

static inline int dazuko_slot_state(struct slot *s)
{
	int state;

/* DOWN */
	call_xp_down(&(s->mutex));

	state = s->state;

	call_xp_up(&(s->mutex));
/* UP */

	return state;
}

static int one_slot_state_not_condition(void *param)
{
	return (dazuko_slot_state(((struct one_slot_state_not_condition_param *)param)->slot)
		!= ((struct one_slot_state_not_condition_param *)param)->state);
}

static int two_slot_state_not_condition(void *param)
{
	return (dazuko_slot_state(((struct two_slot_state_not_condition_param *)param)->slot1)
		!= ((struct two_slot_state_not_condition_param *)param)->state1
		&& dazuko_slot_state(((struct two_slot_state_not_condition_param *)param)->slot2)
		!= ((struct two_slot_state_not_condition_param *)param)->state2);
}

static inline int __dazuko_change_slot_state(struct slot *s, int from_state, int to_state)
{
	/* Make a predicted state transition. We fail if it
	 * is an unpredicted change. We can ALWAYS go to the
	 * to_state if it is the same as from_state. Not SMP safe! */

	if (to_state != from_state)
	{
		/* make sure this is a predicted transition and there
		 * is a daemon on this slot (unique != 0)*/
		if (s->state != from_state || s->did.unique == 0)
			return 0;
	}

	s->state = to_state;

	/* handle appropriate wake_up's for basic
	 * state changes */

	return 1;
}

static int dazuko_change_slot_state(struct slot *s, int from_state, int to_state, int release)
{
	/* SMP safe version of __dazuko_change_slot_state().
	 * This should only be used if we haven't
	 * already aquired slot.mutex. Use this function
	 * with CAUTION, since the mutex may or may not
	 * be released depending on the return value AND
	 * on the value of the "release" argument. */

	int	success;

/* DOWN */
	call_xp_down(&(s->mutex));

	success = __dazuko_change_slot_state(s, from_state, to_state);

	/* the mutex is released if the state change was
	 * unpredicted or if the called wants it released */
	if (!success || release)
		call_xp_up(&(s->mutex));

/* UP? */

	return success;
}

static struct slot * _dazuko_find_slot(struct daemon_id *did, int release, struct slot_list *sl)
{
	/* Find the first slot with the same given
	 * pid number. SMP safe. Use this function
	 * with CAUTION, since the mutex may or may not
	 * be released depending on the return value AND
	 * on the value of the "release" argument. */

	int	i;
	struct slot	*s = NULL;

	if (sl == NULL)
	{
		call_xp_print("dazuko: invalid slot_list given (bug!)\n");
		return NULL;
	}

	for (i=0 ; i<NUM_SLOTS ; i++)
	{
		s = &(sl->slots[i]);
/* DOWN */
		call_xp_down(&(s->mutex));

		if (did == NULL)
		{
			/* we are looking for an empty slot */
			if (s->did.unique == 0 && s->did.xp_id == NULL)
			{
				/* we release the mutex only if the
	 			* called wanted us to */
				if (release)
					call_xp_up(&(s->mutex));

/* UP? */

				return s;
			}
		}
		else if (s->did.unique == 0 && s->did.xp_id == NULL)
		{
			/* this slot is emtpy, so it can't match */

			/* do nothing */
		}
		/* xp_id's must match! */
		else if (call_xp_id_compare(s->did.xp_id, did->xp_id, 0) == DAZUKO_SAME)
		{
			/* unique's must also match (unless unique is negative,
			 * in which case we will trust xp_id) */
			if (did->unique < 0 || (s->did.unique == did->unique))
			{
				/* we release the mutex only if the
				 * called wanted us to */
				if (release)
					call_xp_up(&(s->mutex));

/* UP? */

				return s;
			}
		}

		call_xp_up(&(s->mutex));
/* UP */
	}

	return NULL;
}

static struct slot * dazuko_find_slot_and_slotlist(struct daemon_id *did, int release, struct slot_list *slist, struct slot_list **sl_result)
{
	struct slot		*s;
	int			i;
	struct slot_list	*sl;

	if (slist == NULL)
	{
		for (i=0 ; i<NUM_SLOT_LISTS ; i++)
		{
/* DOWN */
			call_xp_down(&(slot_lists[i].mutex));

			sl = slot_lists[i].slot_list;

			call_xp_up(&(slot_lists[i].mutex));
/* UP */

			if (sl != NULL)
			{
				s = _dazuko_find_slot(did, release, sl);
				if (s != NULL)
				{
					/* set the current slot_list */
					if (sl_result != NULL)
						*sl_result = sl;

					return s;
				}
			}
		}
	}
	else
	{
		return _dazuko_find_slot(did, release, slist);
	}

	return NULL;
}

static inline struct slot * dazuko_find_slot(struct daemon_id *did, int release, struct slot_list *slist)
{
	return dazuko_find_slot_and_slotlist(did, release, slist, NULL);
}

static int dazuko_insert_path_fs(struct dazuko_path **list, struct xp_rwlock *lock_lists, char *fs_path, int fs_len)
{
	/* Create a new struct dazuko_path structure and insert it
	 * into the linked list given (list argument).
	 * The fs_len argument is to help speed things
	 * up so we don't have to calculate the length
	 * of fs_path. */

	struct dazuko_path	*newitem;
	struct dazuko_path	*tmp;

	if (list == NULL || lock_lists == NULL || fs_path == NULL || fs_len < 1)
		return XP_ERROR_INVALID;

	/* we want only absolute paths */
	if (!call_xp_is_absolute_path(fs_path))
		return XP_ERROR_INVALID;

	/* create a new struct dazuko_path structure making room for path also */
	newitem = (struct dazuko_path *)call_xp_malloc(sizeof(struct dazuko_path));
	if (newitem == NULL)
		return XP_ERROR_FAULT;

	newitem->path = (char *)call_xp_malloc(fs_len + 1);
	if (newitem->path == NULL)
	{
		call_xp_free(newitem);
		return XP_ERROR_FAULT;
	}

	/* fs_path is already in kernelspace */
	memcpy(newitem->path, fs_path, fs_len);

	newitem->path[fs_len] = 0;

	while (newitem->path[fs_len-1] == 0)
	{
		fs_len--;
		if (fs_len == 0)
			break;
	}

	if (fs_len < 1)
	{
		call_xp_free(newitem->path);
		call_xp_free(newitem);
		return XP_ERROR_INVALID;
	}

	newitem->len = fs_len;

	/* check if this path already exists in the list */
	for (tmp=*list ; tmp ; tmp=tmp->next)
	{
		if (newitem->len == tmp->len)
		{
			if (memcmp(newitem->path, tmp->path, tmp->len) == 0)
			{
				/* we already have this path */

				call_xp_free(newitem->path);
				call_xp_free(newitem);

				return 0;
			}
		}
	}

	DPRINT(("dazuko: adding path %s\n", newitem->path));

	/* add struct dazuko_path to head of linked list */
/* LOCK */
	call_xp_write_lock(lock_lists);
	newitem->next = *list;
	*list = newitem;
	call_xp_write_unlock(lock_lists);
/* UNLOCK */

	return 0;
}

static void dazuko_remove_all_paths(struct slot_list *slist)
{
	/* Empty both include and exclude struct dazuko_path
	 * linked lists. */

	struct dazuko_path	*tmp;

	if (slist == NULL)
		return;

/* LOCK */
	call_xp_write_lock(&(slist->lock_lists));

	/* empty include paths list */
	while (slist->incl_paths)
	{
		tmp = slist->incl_paths;
		slist->incl_paths = slist->incl_paths->next;

		DPRINT(("dazuko: removing incl %s\n", tmp->path));

		if (tmp->path != NULL)
			call_xp_free(tmp->path);
		call_xp_free(tmp);
	}

	/* empty exclude paths list */
	while (slist->excl_paths)
	{
		tmp = slist->excl_paths;
		slist->excl_paths = slist->excl_paths->next;

		DPRINT(("dazuko: removing excl %s\n", tmp->path));

		if (tmp->path != NULL)
			call_xp_free(tmp->path);
		call_xp_free(tmp);
	}

	call_xp_write_unlock(&(slist->lock_lists));
/* UNLOCK */
}

int dazuko_active(void)
{
	if (call_xp_atomic_read(&active) > 0)
		return 1;

	return 0;
}

static int _dazuko_unregister_daemon(struct daemon_id *did)
{
	/* We unregister the daemon by finding the
	 * slot with the same slot->pid as the the
	 * current process id, the daemon. */

	struct slot		*s;
	struct slot_list	*sl;

	DPRINT(("dazuko: dazuko_unregister_daemon() [%d]\n", did->unique));

	/* find our slot and hold the mutex
	 * if we find it */
/* DOWN? */
	s = dazuko_find_slot_and_slotlist(did, 0, NULL, &sl);

	if (s == NULL)
	{
		DPRINT(("dazuko: this daemon not registered [%d]\n", did->unique));

		/* this daemon was not registered */
		return 0;
	}

/* DOWN */

	DPRINT(("dazuko: unregister (found match [%d -> %d])\n", did->unique, s->did.unique));

	/* clearing the unique and pid makes the slot available */
	s->did.unique = 0;
	call_xp_id_free(s->did.xp_id);
	s->did.xp_id = NULL;

	/* reset slot state */
	__dazuko_change_slot_state(s, DAZUKO_FREE, DAZUKO_FREE);

	call_xp_up(&(s->mutex));
/* UP */

	call_xp_atomic_dec(&(sl->use_count));

	/* Remove all the include and exclude paths
	 * if there are no more daemons in this group */

	if (call_xp_atomic_read(&(sl->use_count)) == 0)
	{
		sl->access_mask = 0;
		dazuko_setup_amc_cache();
		dazuko_remove_all_paths(sl);

		/* this was the last daemon in the group */
		call_xp_atomic_dec(&groupcount);
	}

	/* active should always be positive here, but
	 * let's check just to be sure. ;) */
	if (call_xp_atomic_read(&active) > 0)
	{
		/* active and the kernel usage counter
		 * should always reflect how many daemons
		 * are active */

		call_xp_atomic_dec(&active);
	}
	else
	{
		call_xp_print("dazuko: active count error (possible bug)\n");
	}

	/* slot->state has changed to FREE, notifiy appropriate queues */
	/* we need to notify all slot queues because unique could be -1,
	 * which means that it is possible that this process does not
	 * really belong to this slot */
	call_xp_notify(&(s->wait_daemon_waiting_until_this_slot_not_DONE));
	call_xp_notify(&(s->wait_kernel_waiting_until_this_slot_not_WAITING_and_not_WORKING));
	call_xp_notify(&(s->wait_daemon_waiting_until_this_slot_not_READY));

	/* slotlist->use_count has been decreased, notify appropriate queue */
	call_xp_notify(&(sl->wait_kernel_waiting_for_any_READY_slot_or_zero_use_count));

	return 0;
}

int dazuko_unregister_daemon(struct xp_daemon_id *xp_id)
{
	struct daemon_id	did;
	int			ret;

	if (xp_id == NULL)
		return 0;

	did.unique = -1;
	did.xp_id = call_xp_id_copy(xp_id);

	ret = _dazuko_unregister_daemon(&did);

	call_xp_id_free(did.xp_id);

	return ret;
}

static inline struct slot_list* find_slot_list_from_groupname(const char *group_name)
{
	int			i;
	struct slot_list	*sl;
	const char		*p1;
	const char		*p2;

	for (i=0 ; i<NUM_SLOT_LISTS ; i++)
	{
/* DOWN */
		call_xp_down(&(slot_lists[i].mutex));

		sl = slot_lists[i].slot_list;

		call_xp_up(&(slot_lists[i].mutex));
/* UP */

		if (sl != NULL)
		{
			p1 = group_name;
			p2 = sl->reg_name;

			while (*p1 == *p2)
			{
				if (*p1 == 0)
					break;

				p1++;
				p2++;
			}

			if (*p1 == *p2)
				return sl;
		}
	}

	return NULL;
}

static int dazuko_register_daemon(struct daemon_id *did, const char *reg_name, int string_length, int write_mode)
{
	const char		*p1;
	char			*p2;
	struct slot		*s;
	struct slot_list	*sl;
	int			i;
	struct xp_daemon_id	*tempid;

	DPRINT(("dazuko: dazuko_register_daemon() [%d]\n", did->unique));

	if (did == NULL || reg_name == NULL)
		return XP_ERROR_PERMISSION;

	s = dazuko_find_slot(did, 1, NULL);

	if (s != NULL)
	{
		/* We are already registered! */

		call_xp_print("dazuko: daemon %d already assigned to slot[%d]\n", did->unique, s->id);

		return XP_ERROR_PERMISSION;
	}

	/* Find the slot_list with the matching name. */

	sl = find_slot_list_from_groupname(reg_name);

	if (sl == NULL)
	{
		/* There is no slot_list with this name. We
		 * need to make one. */

		sl = (struct slot_list *)call_xp_malloc(sizeof(struct slot_list));
		if (sl == NULL)
			return XP_ERROR_FAULT;

		dazuko_bzero(sl, sizeof(struct slot_list));

		sl->reg_name = call_xp_malloc(string_length + 1);
		if (sl->reg_name == NULL)
		{
			call_xp_free(sl);
			return XP_ERROR_FAULT;
		}
		dazuko_bzero(sl->reg_name, string_length + 1);

		call_xp_atomic_set(&(sl->use_count), 0);
		call_xp_init_rwlock(&(sl->lock_lists));
#ifdef TRUSTED_APPLICATION_SUPPORT
		call_xp_init_rwlock(&(sl->lock_trusted_list));
#endif
		call_xp_init_queue(&(sl->wait_kernel_waiting_for_any_READY_slot_or_zero_use_count));

		p1 = reg_name;
		p2 = sl->reg_name;

		while (*p1)
		{
			*p2 = *p1;

			p1++;
			p2++;
		}
		*p2 = 0;

		/* give each slot a unique id and assign slot_list */
		for (i=0 ; i<NUM_SLOTS ; i++)
		{
			sl->slots[i].id = i;
			sl->slots[i].slot_list = sl;
			call_xp_init_mutex(&(sl->slots[i].mutex));
			call_xp_init_queue(&(sl->slots[i].wait_daemon_waiting_until_this_slot_not_READY));
			call_xp_init_queue(&(sl->slots[i].wait_kernel_waiting_until_this_slot_not_WAITING_and_not_WORKING));
			call_xp_init_queue(&(sl->slots[i].wait_daemon_waiting_until_this_slot_not_DONE));
		}

		/* we need to find an empty slot */
		for (i=0 ; i<NUM_SLOT_LISTS ; i++)
		{
/* DOWN */
			call_xp_down(&(slot_lists[i].mutex));

			if (slot_lists[i].slot_list == NULL)
			{
				slot_lists[i].slot_list = sl;

				call_xp_up(&(slot_lists[i].mutex));
/* UP */
				break;
			}

			call_xp_up(&(slot_lists[i].mutex));
/* UP */
		}

		if (i == NUM_SLOT_LISTS)
		{
			/* no empty slot :( */

			call_xp_free(sl->reg_name);
			call_xp_free(sl);

			return XP_ERROR_BUSY;
		}
	}

	tempid = call_xp_id_copy(did->xp_id);

	/* find an available slot and hold the mutex
	 * if we find one */
/* DOWN? */
	s = dazuko_find_slot(NULL, 0, sl);

	if (s == NULL)
	{
		call_xp_id_free(tempid);
		return XP_ERROR_BUSY;
	}

/* DOWN */

	/* We have found a slot, so increment the active
	 * variable and the kernel module use counter.
	 * The module counter will always reflect the
	 * number of daemons. */

	call_xp_atomic_inc(&active);

	/* get new unique id for this process */
	did->unique = dazuko_get_new_unique();

	s->did.unique = did->unique;
	s->did.xp_id = tempid;
	s->write_mode = write_mode;

	call_xp_atomic_inc(&(sl->use_count));

	if (call_xp_atomic_read(&(sl->use_count)) == 1)
	{
		/* this is the first daemon in the group */
		call_xp_atomic_inc(&groupcount);
	}

	/* the daemon is registered, but not yet
	 * ready to receive files */
	__dazuko_change_slot_state(s, DAZUKO_FREE, DAZUKO_FREE);

	DPRINT(("dazuko: slot[%d] assigned to daemon %d\n", s->id, s->did.unique));

	call_xp_up(&(s->mutex));
/* UP */

	/* although there was a state change, we don't need to notify any queues
	 * because a new slot is first interesting when it hits the READY state */

	return 0;
}

static struct slot* dazuko_get_an_access(struct daemon_id *did)
{
	/* The daemon is requesting a filename of a file
	 * to scan. This code will wait until a filename
	 * is available, or until we should be killed.
	 * (killing is done if any errors occur as well
	 * as when the user kills us) */

	/* If a slot is returned, it will be already locked! */

	int					i;
	struct slot					*s;
	struct one_slot_state_not_condition_param	cond_p;

tryagain:
	/* find our slot */
	s = dazuko_find_slot(did, 1, NULL);

	if (s == NULL)
	{
		i = dazuko_register_daemon(did, "_COMPAT", 7, 1);
		if (i != 0)
		{
			call_xp_print("dazuko: unregistered daemon %d attempted to get access\n", did->unique);
			return NULL;
		}

		s = dazuko_find_slot(did, 1, NULL);
		if (s == NULL)
		{
			call_xp_print("dazuko: unregistered daemon %d attempted to get access\n", did->unique);
			return NULL;
		}

		call_xp_print("dazuko: warning: daemon %d is using a deprecated protocol\n", did->unique);
	}

	/* the daemon is now ready to receive a file */

	if (!dazuko_change_slot_state(s, DAZUKO_FREE, DAZUKO_READY, 1))
	{
		/* this is an unexpected state change, but it can happen due
		 * to signals interrupting the registered daemon and causing
		 * the daemon to retry getting an access */

		/* force change (because daemon is ready) */
		dazuko_change_slot_state(s, DAZUKO_READY, DAZUKO_READY, 1);

		/* unexpected state change, notify other kernel queue */
		call_xp_notify(&(s->wait_kernel_waiting_until_this_slot_not_WAITING_and_not_WORKING));
	}

	/* slot->state has changed to READY, notify appropriate queue */
	call_xp_notify(&(s->slot_list->wait_kernel_waiting_for_any_READY_slot_or_zero_use_count));

	cond_p.slot = s;
	cond_p.state = DAZUKO_READY;
	if (call_xp_wait_until_condition(&(s->wait_daemon_waiting_until_this_slot_not_READY), one_slot_state_not_condition, &cond_p, 1) != 0)
	{
		/* The user has issued an interrupt.
		 * Return an error. The daemon should
		 * unregister itself. */

		DPRINT(("dazuko: daemon %d killed while waiting for work\n", did->unique));

		if (dazuko_change_slot_state(s, DAZUKO_READY, DAZUKO_BROKEN, 1) || dazuko_change_slot_state(s, DAZUKO_WAITING, DAZUKO_BROKEN, 1))
		{
			/* slot->state has changed to BROKEN, notifiy appropriate queue */
			call_xp_notify(&(s->wait_kernel_waiting_until_this_slot_not_WAITING_and_not_WORKING));
		}

		return NULL;
	}

	/* slot SHOULD now be in DAZUKO_WAITING state */

	/* we will be working with the slot, so
	 * we need to lock it */

/* DOWN? */
	if (!dazuko_change_slot_state(s, DAZUKO_WAITING, DAZUKO_WORKING, 0))
	{
		/* State transition error. Try again., */

		goto tryagain;
	}

/* DOWN */

	/* Slot IS in DAZUKO_WORKING state. Copy all the
	 * necessary information to userspace structure. */

	/* IMPORTANT: slot is still locked! */

	return s;  /* access is available */
}

static int dazuko_initialize_cache(struct daemon_id *did, unsigned long ttl)
{
	/* find our slot */
	if (dazuko_find_slot(did, 1, NULL) == NULL)
	{
		/* this daemon is not registered! */

		return -1;
	}

	return call_xp_init_cache(ttl);
}

static int dazuko_return_access(struct daemon_id *did, int response, struct slot *s)
{
	/* The daemon has finished scanning a file
	 * and has the response to give. The daemon's
	 * slot should be in the DAZUKO_WORKING state. */

	struct one_slot_state_not_condition_param	cond_p;

	if (s == NULL)
		return -1;

	/* we will be writing into the slot, so we
	 * need to lock it */

/* DOWN? */
	if (!dazuko_change_slot_state(s, DAZUKO_WORKING, DAZUKO_DONE, 0))
	{
		/* The slot is in the wrong state. We will
		 * assume the kernel has cancelled the file
		 * access. */

		DPRINT(("dazuko: response from daemon %d on slot[%d] not needed\n", did->unique, s->id));

		return 0;
	}

/* DOWN */

	s->response = response;

	call_xp_up(&(s->mutex));
/* UP */

	/* slot->state has changed to DONE, notifiy appropriate queues */
	call_xp_notify(&(s->wait_kernel_waiting_until_this_slot_not_WAITING_and_not_WORKING));

	cond_p.slot = s;
	cond_p.state = DAZUKO_DONE;
	if (call_xp_wait_until_condition(&(s->wait_daemon_waiting_until_this_slot_not_DONE), one_slot_state_not_condition, &cond_p, 1) != 0)
	{
		/* The user has issued an interrupt.
		 * Return an error. The daemon should
		 * unregister itself. */

		DPRINT(("dazuko: daemon %d killed while waiting for response acknowledgement\n", did->unique));

		return XP_ERROR_INTERRUPT;
	}

	return 0;
}

static inline int dazuko_isdigit(const char c)
{
	return (c >= '0' && c <= '9');
}

inline unsigned long dazuko_strtoul(const char *string)
{
	unsigned long	num = 1;
	const char	*p = string;

	if (string == NULL)
		return 0;

	if (dazuko_isdigit(*p))
	{
		num *= *p - '0';
		p++;
	}
	else
	{
		return 0;
	}

	while (dazuko_isdigit(*p))
	{
		num *= 10;
		num += *p - '0';
		p++;
	}

	return num;
}

static inline long dazuko_strtol(const char *string)
{
	const char	*p = string;

	if (string == NULL)
		return 0;

	switch (*p)
	{
		case '-':
			p++;
			return (-1 * ((long)(dazuko_strtoul(p))));

		case '+':
			p++;
			break;
	}

	return (long)dazuko_strtoul(p);
}

inline int dazuko_strlen(const char *string)
{
	const char	*p;

	if (string == NULL)
		return -1;

	for (p=string ; *p ; p++)
		continue;

	return (p - string);
}

static inline const char* dazuko_strchr(const char *haystack, char needle)
{
	const char	*p;

	if (haystack == NULL)
		return NULL;

	for (p=haystack ; *p ; p++)
	{
		if (*p == needle)
			return p;
	}

	return NULL;
}

static inline const char* dazuko_strstr(const char *haystack, const char *needle)
{
	const char	*p1;
	const char	*p2;
	const char	*p3;

	if (haystack == NULL || needle == NULL)
		return NULL;

	for (p1=haystack ; *p1 ; p1++)
	{
		for (p2=needle,p3=p1 ; *p2&&*p3 ; p2++,p3++)
		{
			if (*p2 != *p3)
				break;
		}

		if (*p2 == 0)
			return p1;
	}

	return NULL;
}

int dazuko_get_value(const char *key, const char *string, char **value)
{
	const char	*p1;
	const char	*p2;
	int		size;

	if (value == NULL)
		return -1;

	*value = NULL;

	if (key == NULL || string == NULL)
		return -1;

	p1 = dazuko_strstr(string, key);
	if (p1 == NULL)
		return -1;

	p1 += dazuko_strlen(key);

	for (p2=p1 ; *p2 && *p2!='\n' ; p2++)
		continue;

	size = (p2 - p1) + 1;
	*value = call_xp_malloc(size);
	if (*value == NULL)
		return -1;

	memcpy(*value, p1, size - 1);
	(*value)[size - 1] = 0;

	return 0;
}

static inline void dazuko_clear_replybuffer(struct dazuko_request *request)
{
	dazuko_bzero(request->reply_buffer, request->reply_buffer_size);
	request->reply_buffer_size_used = 0;
}

static inline void dazuko_close_replybuffer(struct dazuko_request *request)
{
	request->reply_buffer[request->reply_buffer_size_used] = 0;
	request->reply_buffer_size_used++;
}

static void dazuko_add_keyvalue_to_replybuffer(struct dazuko_request *request, const char *key, void *value, char vtype)
{

#define DAZUKO_VSNPRINT(type, name) dazuko_snprintf(request->reply_buffer + request->reply_buffer_size_used, (request->reply_buffer_size - request->reply_buffer_size_used), "%s%" #type , key, *((name *)value))

	switch (vtype)
	{
		case 'd':
			DAZUKO_VSNPRINT(d, const int);
			break;

		case 's':
			DAZUKO_VSNPRINT(s, const char *);
			break;

		case 'l':
			DAZUKO_VSNPRINT(lu, const unsigned long);
			break;

		default:
			/* all other types treated as chars */
			DAZUKO_VSNPRINT(c, const char);
			break;
	}

	/* update how much buffer we have used */
	request->reply_buffer_size_used += dazuko_strlen(request->reply_buffer + request->reply_buffer_size_used);
}

static inline int dazuko_printable(char c)
{
	/* hopefully this counts for all operating systems! */

	return ((c >= ' ') && (c <= '~') && (c != '\\'));
}

static inline void dazuko_add_esc_to_replybuffer(struct dazuko_request *request, const char *key, char **filename)
{
	int		found = 0;
	char		*p_rq;
	const char	*limit;
	const char	*p_fn;
	unsigned char	c;

	/* check for escape characters in filename */
	for (p_fn=*filename ; *p_fn ; p_fn++)
	{
		if (!dazuko_printable(*p_fn))
		{
			found = 1;
			break;
		}
	}

	if (found)
	{
		/* this is expensive, but it will also almost never occur */

		p_rq = request->reply_buffer + request->reply_buffer_size_used;
		limit = request->reply_buffer + request->reply_buffer_size - 1;

		dazuko_snprintf(p_rq, limit - p_rq, "%s", key);
		p_rq += dazuko_strlen(p_rq);

		for (p_fn=*filename ; *p_fn && (p_rq<limit) ; p_fn++)
		{
			if (dazuko_printable(*p_fn))
			{
				*p_rq = *p_fn;
				p_rq++;
			}
			else
			{
				c = *p_fn & 0xFF;
				dazuko_snprintf(p_rq, limit - p_rq, "\\x%02x", c);
				p_rq += dazuko_strlen(p_rq);
			}
		}

		request->reply_buffer_size_used += dazuko_strlen(request->reply_buffer + request->reply_buffer_size_used);
	}
	else
	{
		/* no escape characters found */

		dazuko_add_keyvalue_to_replybuffer(request, key, filename, 's');
	}
}

#ifdef TRUSTED_APPLICATION_SUPPORT
static inline void dazuko_remove_all_trusted(struct slot_list *sl)
{
	struct trusted_container	*tc;

	if (sl == NULL)
		return;

/* LOCK */
	call_xp_write_lock(&(sl->lock_trusted_list));

	while (sl->trusted_list != NULL)
	{
		tc = sl->trusted_list;
		sl->trusted_list = sl->trusted_list->next;
		call_xp_id_free(tc->xp_id);
		call_xp_free(tc->token);
		call_xp_free(tc);
	}

	call_xp_write_unlock(&(sl->lock_trusted_list));
/* UNLOCK */
}

static inline void dazuko_remove_trusted(struct slot_list *sl, char *token, int token_length)
{
	struct trusted_container	*cur = NULL;
	struct trusted_container	*prev = NULL;
	struct trusted_container	*temp = NULL;

/* LOCK */
	call_xp_write_lock(&(sl->lock_trusted_list));

	cur = sl->trusted_list;
	while (cur != NULL)
	{
		if (token_length != cur->token_length)
			continue;

		if (memcmp(token, cur->token, token_length) == 0)
		{
			/* delete this container */

			temp = cur;

			cur = cur->next;

			if (prev == NULL)
			{
				sl->trusted_list = cur;
			}
			else
			{
				prev->next = cur;
			}

			call_xp_id_free(temp->xp_id);
			call_xp_free(temp->token);
			call_xp_free(temp);
		}
		else
		{
			prev = cur;
			cur = cur->next;
		}
	}

	call_xp_write_unlock(&(sl->lock_trusted_list));
/* UNLOCK */
}
#endif

static int dazuko_set_option(struct daemon_id *did, int opt, void *param, int len)
{
	/* The daemon wants to set a configuration
	 * option in the kernel. */

	struct slot		*s;
	struct slot_list	*sl;
	int			error = 0;

	/* sanity check */
	if (len < 0 || len > 8192)
		return XP_ERROR_PERMISSION;

	/* make sure we are already registered
	 * (or that we don't register twice) */

	/* find our slot */
	s = dazuko_find_slot_and_slotlist(did, 1, NULL, &sl);

	switch (opt)
	{
		case REGISTER:
			call_xp_print("dazuko: dazuko_set_option does not support REGISTER (bug!)\n");
			return XP_ERROR_PERMISSION;

		case UNREGISTER:
			if (s == NULL)
			{
				/* We are not registered! */

				return 0;
			}
			break;

		default:
			if (s == NULL)
			{
				error = dazuko_register_daemon(did, "_COMPAT", 7, 1);
				if (error)
				{
					call_xp_print("dazuko: unregistered daemon %d attempted access\n", did->unique);
					return XP_ERROR_PERMISSION;
				}

				s = dazuko_find_slot_and_slotlist(did, 1, NULL, &sl);
				if (s == NULL)
				{
					call_xp_print("dazuko: unregistered daemon %d attempted access\n", did->unique);
					return XP_ERROR_PERMISSION;
				}

				call_xp_print("dazuko: warning: daemon %d is using a deprecated protocol (opt=%d)\n", did->unique, opt);
			}
			break;
	}

	/* check option type and take the appropriate action */
	switch (opt)
	{
		case UNREGISTER:
			error = _dazuko_unregister_daemon(did);
			break;

		case SET_ACCESS_MASK:
			sl->access_mask = (char)dazuko_strtoul((char *)param);

			/* rebuild access_mask_cache */
			dazuko_setup_amc_cache();
			break;

		case ADD_INCLUDE_PATH:
			error = dazuko_insert_path_fs(&(sl->incl_paths), &(sl->lock_lists), (char *)param, len);
			if (!error)
			{
				if (call_xp_set_path((char *)param, ADD_INCLUDE_PATH) != 0)
					error = XP_ERROR_INVALID;
			}
			break;

		case ADD_EXCLUDE_PATH:
			error = dazuko_insert_path_fs(&(sl->excl_paths), &(sl->lock_lists), (char *)param, len);
			if (!error)
			{
				if (call_xp_set_path((char *)param, ADD_EXCLUDE_PATH) != 0)
					error = XP_ERROR_INVALID;
			}
			break;

		case REMOVE_ALL_PATHS:
			dazuko_remove_all_paths(sl);
			break;

#ifdef TRUSTED_APPLICATION_SUPPORT
		case REMOVE_ALL_TRUSTED:
			dazuko_remove_all_trusted(sl);
			break;

		case REMOVE_TRUSTED:
			dazuko_remove_trusted(sl, (char *)param, len);
			break;
#endif

		default:
			error = XP_ERROR_INVALID;
			break;
	}

	return error;
}

static struct slot * dazuko_get_and_hold_ready_slot(struct slot_list *sl)
{
	/* This is a simple search to find a
	 * slot whose state is DAZUKO_READY. This means
	 * it is able to accept work. If a slot
	 * is found, the slot.mutex is held so
	 * it can be filled with work by the caller.
	 * It is the responsibility of the caller
	 * to RELEASE THE MUTEX. */

	int		i;
	struct slot	*s;

	for (i=0 ; i<NUM_SLOTS ; i++)
	{
		s = &(sl->slots[i]);
/* DOWN? */
		if (dazuko_change_slot_state(s, DAZUKO_READY, DAZUKO_WAITING, 0))
		{
/* DOWN */
			return s;
		}
	}

	/* we didn't find a slot that is ready for work */

	return NULL;
}

static int get_ready_slot_condition(void *param)
{
	return ((((struct get_ready_slot_condition_param *)param)->slot = dazuko_get_and_hold_ready_slot(((struct get_ready_slot_condition_param *)param)->slotlist)) != NULL
		|| call_xp_atomic_read(&(((struct get_ready_slot_condition_param *)param)->slotlist->use_count)) == 0);
}

static int dazuko_run_daemon_on_slotlist(unsigned long event, char *filename, int filenamelength, struct event_properties *event_p, struct file_properties *file_p, int prev_response, struct slot_list *sl, struct dazuko_file_struct *dfs)
{
	/* This is the main function called by the kernel
	 * to work with a daemon. */

	int						rc;
	int						unique;
	struct slot					*s;
	struct get_ready_slot_condition_param		cond_p1;
	struct two_slot_state_not_condition_param	cond_p2;

begin:
	/* we initialize the slot value because
	 * we cannot guarentee that it will be
	 * assigned a new value BEFORE !active
	 * is checked */
	s = NULL;

	/* wait for a slot to become ready */
	cond_p1.slotlist = sl;
	cond_p1.slot = s;
	if (call_xp_wait_until_condition(&(sl->wait_kernel_waiting_for_any_READY_slot_or_zero_use_count), get_ready_slot_condition, &cond_p1, 0) != 0)
	{
		/* The kernel process was killed while
		 * waiting for a slot to become ready.
		 * This is fine. */

		DPRINT(("dazuko: kernel process %d killed while waiting for free slot\n", event_p != NULL ? event_p->pid : 0));

		return -1;  /* user interrupted */
	}

	/* Make sure we have a slot. We may have
	 * gotten past the last wait because we
	 * are no longer active. */

	s = cond_p1.slot;

	if (s == NULL)
	{
		/* We were no longer active. We don't
		 * need to initiate a daemon. This also
		 * means we never acquired the lock. */

		return 0;  /* allow access */
	}

/* DOWN */

	/* the slot is already locked at this point */

	/* grab the daemon's unique */
	unique = s->did.unique;

	/* At this point we have a locked slot. It IS
	 * sitting in the DAZUKO_WAITING state, waiting for
	 * us to give it some work. */
	
	/* set up the slot to do work */
	s->filename = filename;
	s->event = event;
	s->response = prev_response;
	s->filenamelength = filenamelength;
	s->dfs = dfs;

	if (event_p == NULL)
		dazuko_bzero(&(s->event_p), sizeof(struct event_properties));
	else
		memcpy(&(s->event_p), event_p, sizeof(struct event_properties));

	if (file_p == NULL)
		dazuko_bzero(&(s->file_p), sizeof(struct file_properties));
	else
		memcpy(&(s->file_p), file_p, sizeof(struct file_properties));

	/* we are done modifying the slot */
	call_xp_up(&(s->mutex));
/* UP */

	/* slot->state has changed to WAITING, notifiy appropriate queues */
	call_xp_notify(&(s->wait_daemon_waiting_until_this_slot_not_READY));

	/* wait until the daemon is finished with the slot */
	cond_p2.slot1 = s;
	cond_p2.state1 = DAZUKO_WAITING;
	cond_p2.slot2 = s;
	cond_p2.state2 = DAZUKO_WORKING;
	if (call_xp_wait_until_condition(&(s->wait_kernel_waiting_until_this_slot_not_WAITING_and_not_WORKING), two_slot_state_not_condition, &cond_p2, 0) != 0)
	{
		/* The kernel process was killed while
		 * waiting for a daemon to process the file.
		 * This is fine. */

		DPRINT(("dazuko: kernel process %d killed while waiting for daemon response\n", event_p->pid));

		/* change the slot's state to let the
		 * daemon know we are not interested
		 * in a response */
		dazuko_change_slot_state(s, DAZUKO_FREE, DAZUKO_FREE, 1);

		/* slot->state has changed to FREE, notifiy appropriate queue */
		call_xp_notify(&(s->wait_daemon_waiting_until_this_slot_not_DONE));

		return -1;  /* user interrupted */
	}

	/* we are working with the slot, so
	 * we need to lock it */
/* DOWN */
	call_xp_down(&(s->mutex));

	/* make sure this is the right daemon */
	if (s->did.unique != unique)
	{
		/* This is a different daemon than
		 * the one we assigned work to.
		 * We need to scan again. */
		call_xp_up(&(s->mutex));
/* UP */
		goto begin;
	}

	/* The slot should now be in the DAZUKO_DONE state. */
	if (!__dazuko_change_slot_state(s, DAZUKO_DONE, DAZUKO_FREE))
	{
		/* The daemon was killed while scanning.
		 * We need to scan again. */

		call_xp_up(&(s->mutex));
/* UP */
		goto begin;
	}

	/* grab the response */
	rc = s->response;

	call_xp_up(&(s->mutex));
/* UP */

	/* slot->state has changed to FREE, notifiy appropriate queue */
	call_xp_notify(&(s->wait_daemon_waiting_until_this_slot_not_DONE));

	/* CONGRATULATIONS! You successfully completed a full state cycle! */

	return rc;
}

static int dazuko_is_selected(struct dazuko_file_struct *kfs, struct slot_list *slist)
{
	/* Check if the given filename (with path) is
	 * under our include directories but not under
	 * the exclude directories. */

	struct dazuko_file_listnode	*cur;
	struct dazuko_path		*path;
	int				selected = 0;
	int				use_aliases = 1;

	if (kfs == NULL || slist == NULL)
		return 0;

	if (kfs->aliases == NULL && kfs->filename != NULL)
	{
		/* extension is not using aliases */

		use_aliases = 0;

		kfs->aliases = (struct dazuko_file_listnode *)xp_malloc(sizeof(struct dazuko_file_listnode));
		if (kfs->aliases == NULL)
		{
			call_xp_print("dazuko: warning: access not controlled (%s)\n", kfs->filename);
			return 0;
		}

		dazuko_bzero(kfs->aliases, sizeof(struct dazuko_file_listnode));

		kfs->aliases->filename = kfs->filename;
		kfs->aliases->filename_length = kfs->filename_length;
	}

/* LOCK */
	call_xp_read_lock(&(slist->lock_lists));

	for (cur=kfs->aliases ; cur ; cur=cur->next)
	{
		if (cur->filename != NULL && cur->filename_length > 0)
		{
			/* check if filename is under our include paths */
			for (path=slist->incl_paths ; path ; path=path->next)
			{
				/* the include item must be at least as long as the given filename */
				if (path->len <= cur->filename_length)
				{
					/* the include item should match the beginning of the given filename */
					if (memcmp(path->path, cur->filename, path->len) == 0)
					{
						kfs->filename = cur->filename;
						kfs->filename_length = cur->filename_length;

						selected = 1;
						break;
					}
				}
			}

			/* If we didn't find a path, it isn't in our
			 * include directories. It can't be one of
			 * the selected files to scan. */
			if (!selected)
			{
				continue;
			}

			/* check if filename is under our exclude paths */
			for (path=slist->excl_paths ; path ; path=path->next)
			{
				/* the exclude item must be at least as long as the given filename */
				if (path->len <= cur->filename_length)
				{
					/* the exclude item should match the beginning of the given filename */
					if (memcmp(path->path, cur->filename, path->len) == 0)
					{
						kfs->filename = NULL;
						kfs->filename_length = 0;

						selected = 0;
						break;
					}
				}
			}

			/* If we are still selected, then we can stop. */
			if (selected)
				break;
		}
	}

	call_xp_read_unlock(&(slist->lock_lists));
/* UNLOCK */

	if (!use_aliases)
	{
		call_xp_free(kfs->aliases);
		kfs->aliases = NULL;
	}

	return selected;
}

static inline int dazuko_should_scan(struct dazuko_file_struct *kfs, struct slot_list *slist)
{
	/* Check if we are supposed to scan this file.
	 * This checks for all the correct file types,
	 * permissions, and if it is within the desired
	 * paths to scan. */

	int result = 0;

	/* make necessary platform-dependent checks */
	if (call_xp_fill_file_struct(kfs) == 0)
	{
		if (dazuko_is_selected(kfs, slist))
			result = 1;
	}

	return result;
}

static inline int dazuko_run_daemon(unsigned long event, struct dazuko_file_struct *dfs, struct event_properties *event_p, struct slot_list *skip_slotlist)
{
	struct slot_list	*sl;
	int			i;
	int			index;
	int			j;
	int			rc = 0;
	int			error;

	i = dazuko_event2index(event);
	if (i < 0 || i >= NUM_EVENTS)
	{
		call_xp_print("dazuko: unknown event:%lu, allowing access (possible bug)\n", event);
		return 0;
	}

	for (index=0 ; index<NUM_SLOT_LISTS ; index++)
	{
/* DOWN */
		call_xp_down(&mutex_amc);

		j = access_mask_cache[i][index];

		call_xp_up(&mutex_amc);
/* UP */

		if (j == AMC_UNSET)
			break;

		if (j < 0 || j >= NUM_SLOT_LISTS)
		{
			call_xp_print("dazuko: illegal value:%d in access_mask_cache (possible bug)\n", j);
			break;
		}
	
/* DOWN */
		call_xp_down(&(slot_lists[j].mutex));

		sl = slot_lists[j].slot_list;

		call_xp_up(&(slot_lists[j].mutex));
/* UP */

		if (sl == NULL)
			continue;

		if (sl == skip_slotlist)
			continue;

#ifdef ANONYMOUS_RESOLVE
		if (!dazuko_should_scan(dfs, sl))
			continue;

		error = dazuko_run_daemon_on_slotlist(event, dfs->filename, dfs->filename_length, event_p, &(dfs->file_p), rc, sl, NULL);
#else
		error = dazuko_run_daemon_on_slotlist(event, NULL, 0, event_p, NULL, rc, sl, dfs);
#endif

		if (error < 0)
		{
			/* most likely user interrupt */
			rc = error;
			break;
		}
		else if (error > 0)
		{
			/* this daemon wants access blocked */
			rc = 1;
		}
	}

	return rc;
}

static inline struct trusted_container * _remove_trusted_node(struct trusted_container *prev, struct trusted_container *cur, struct slot_list *sl)
{
	struct trusted_container	*next;

	if (cur == NULL || sl == NULL)
		return NULL;

	next = cur->next;

	if (prev != NULL)
		prev->next = next; 
	else
		sl->trusted_list = next;

	/* remove this trusted container */
	call_xp_id_free(cur->xp_id);
	call_xp_free(cur->token);
	call_xp_free(cur);

	return next;
}

inline int dazuko_is_our_daemon(struct xp_daemon_id *xp_id, struct slot_list **slotlist, struct slot **slot)
{
	/* Check if the current process is one
	 * of the daemons. */

	int				ret = 0;
	struct daemon_id		did;
	struct slot			*s;
	int				i;
	struct slot_list		*sl;
#ifdef TRUSTED_APPLICATION_SUPPORT
	int				cmp;
	struct trusted_container	*tc;
	struct trusted_container	*prev;
#endif

	did.xp_id = call_xp_id_copy(xp_id);
	did.unique = -1;

	for (i=0 ; i<NUM_SLOT_LISTS ; i++)
	{
/* DOWN */
		call_xp_down(&(slot_lists[i].mutex));

		sl = slot_lists[i].slot_list;

		call_xp_up(&(slot_lists[i].mutex));
/* UP */

		if (sl == NULL)
			continue;

		s = _dazuko_find_slot(&did, 1, sl);
		if (s != NULL)
		{
			ret = 1;

			if (slotlist != NULL)
				*slotlist = sl;

			if (slot != NULL)
				*slot = s;

			break;
		}

		if (did.xp_id == NULL)
			continue;

#ifdef TRUSTED_APPLICATION_SUPPORT
		/* This boolean is not protected by a lock on purpose.
		 * It is used as optimization when there are no trusted
		 * processes. If it is set, then we will use the lock. */
		if (!(sl->set_trusted_list))
			continue;

/* LOCK */
		call_xp_write_lock(&(sl->lock_trusted_list));

		tc = sl->trusted_list;
		prev = NULL;
		while (tc != NULL)
		{
			cmp = call_xp_id_compare(tc->xp_id, did.xp_id, 1);

			if (cmp == DAZUKO_SAME || (cmp == DAZUKO_CHILD && tc->trust_children))
			{
				ret = 1;

				if (slotlist != NULL)
					*slotlist = sl;

				break;
			}
			else if (cmp == DAZUKO_SUSPICIOUS)
			{
				DPRINT(("dazuko: detected suspicios activity, removing trusted daemon [%d]\n", did.unique));

				/* remove invalid trusted node */
				tc = _remove_trusted_node(prev, tc, sl);
				break;
			}
			else
			{
				prev = tc;
				tc = tc->next;
			}
		}

		call_xp_write_unlock(&(sl->lock_trusted_list));
/* UNLOCK */

		if (ret)
			break;
#endif
	}

	call_xp_id_free(did.xp_id);

	return ret;
}

inline char* dazuko_strdup(const char *string, int *newlength)
{
	int	length;
	char	*newstring;

	if (string == NULL)
		return NULL;

	length = dazuko_strlen(string);

	newstring = (char *)call_xp_malloc(length + 1);

	if (newstring == NULL)
		return NULL;

	memcpy(newstring, string, length);
	newstring[length] = 0;

	if (newlength != NULL)
		*newlength = length;

	return newstring;
}

#ifdef TRUSTED_APPLICATION_SUPPORT
static inline int dazuko_add_trusted_daemon(struct xp_daemon_id *xp_id, const char *token, int trust_children, struct slot_list *sl)
{
	int				error = 0;
	struct trusted_container	*tc;
	struct trusted_container	*temp_tc = NULL;
	char				*token_copy;
	int				token_length;

	token_copy = dazuko_strdup(token, &token_length);
	if (token_copy == NULL)
	{
		error = -1;
		goto out;
	}

	temp_tc = (struct trusted_container *)call_xp_malloc(sizeof(struct trusted_container));
	if (temp_tc == NULL)
	{
		error = -1;
		goto out;
	}

	temp_tc->xp_id = call_xp_id_copy(xp_id);
	if (temp_tc->xp_id == NULL)
	{
		error = -1;
		goto out;
	}

/* LOCK */
	call_xp_read_lock(&(sl->lock_trusted_list));

	tc = sl->trusted_list;
	while (tc != NULL)
	{
		if (call_xp_id_compare(tc->xp_id, xp_id, 0) == DAZUKO_SAME)
		{
			/* This process is already registered.
			 * but we will assign the new token. */

			call_xp_free(tc->token);
			tc->token = token_copy;
			token_copy = NULL;
			tc->token_length = token_length;
			tc->trust_children = trust_children;
			break;
		}
		tc = tc->next;
	}

	if (tc == NULL)
	{
		/* we need to add the process to the list */

		temp_tc->next = sl->trusted_list;
		temp_tc->token = token_copy;
		token_copy = NULL;
		temp_tc->token_length = token_length;
		temp_tc->trust_children = trust_children;
		sl->trusted_list = temp_tc;
		temp_tc = NULL;

		/* set the flag if necessary */
		if (!(sl->set_trusted_list))
			sl->set_trusted_list = 1;
	}

	call_xp_read_unlock(&(sl->lock_trusted_list));
/* UNLOCK */

out:
	if (temp_tc != NULL)
	{
		if (temp_tc->xp_id != NULL)
			call_xp_id_free(temp_tc->xp_id);

		call_xp_free(temp_tc);
	}

	if (token_copy != NULL)
		call_xp_free(token_copy);

	return error;
}

static inline int dazuko_register_trusted_daemon(struct xp_daemon_id *xp_id, const char *group_name, char *token, char *trust_flags)
{
	struct event_properties	event_p;
	struct slot_list	*sl;
	int			rc;
	int			trust_children = 0;

	if (xp_id == NULL || group_name == NULL || token == NULL)
		return -1;

	sl = find_slot_list_from_groupname(group_name);

	if (sl == NULL)
		return -1;

	/* check if this group is accepting trust requests */
	if ((DAZUKO_TRUST_REQUEST & sl->access_mask) == 0)
		return -1;

	memset(&event_p, 0, sizeof(event_p));

	/* set general event information (for example, PID) */
	call_xp_set_event_properties(&event_p, xp_id);

	if (trust_flags != NULL)
	{
		if (dazuko_strchr(trust_flags, 'C') != NULL)
		{
			event_p.flags = DAZUKO_TRUST_CHILDREN;
			trust_children = 1;
		}
	}

	/* prev_response is set to 1 so that trust requests
	 * are blocked by default */

	rc = dazuko_run_daemon_on_slotlist(DAZUKO_TRUST_REQUEST, token, dazuko_strlen(token), &event_p, NULL, 1, sl, NULL);

	if (rc == 0)
	{
		/* process may be added to trusted list */

		rc = dazuko_add_trusted_daemon(xp_id, token, trust_children, sl);
	}

	return rc;
}

static inline int dazuko_unregister_trusted_daemon(struct xp_daemon_id *xp_id)
{
	struct trusted_container	*prev;
	struct trusted_container	*cur;
	int				error = -1;
	int				i;
	struct slot_list		*sl;

	for (i=0 ; i<NUM_SLOT_LISTS ; i++)
	{
/* DOWN */
		call_xp_down(&(slot_lists[i].mutex));

		sl = slot_lists[i].slot_list;

		call_xp_up(&(slot_lists[i].mutex));
/* UP */

		if (sl == NULL)
			continue;

		/* This boolean is not protected by a lock on purpose.
		 * It is used as optimization when there are no trusted
		 * processes. If it is set, then we will use the lock. */
		if (!(sl->set_trusted_list))
			continue;

/* LOCK */
		call_xp_write_lock(&(sl->lock_trusted_list));

		prev = NULL;
		cur = sl->trusted_list;
		while (cur != NULL)
		{
			if (call_xp_id_compare(cur->xp_id, xp_id, 0) == DAZUKO_SAME)
			{
				_remove_trusted_node(prev, cur, sl);

				/* we found the process and removed it */
				error = 0;

				break;
			}
			prev = cur;
			cur = cur->next;
		}

		/* set flag to 0 if all trusted processes have been removed */
		if (sl->trusted_list == NULL)
			sl->set_trusted_list = 0;

		call_xp_write_unlock(&(sl->lock_trusted_list));
/* UNLOCK */
	}

	return error;
}
#endif

static int dazuko_handle_request_register(struct dazuko_request *request, struct xp_daemon_id *xp_id)
{
	char			*value1;
	char			*value2;
	int			error = 0;
	struct daemon_id	did;

	/* read "\nRM=regmode\nGN=group" */
	/* send "\nID=id\nVN=versionnumber\nVS=version" */

	if (request->buffer_size <= 0)
		return -1;

	if (request->reply_buffer_size <= 0)
		return -1;

	if (dazuko_get_value("\nGN=", request->buffer, &value1) != 0)
		return -1;

	if (dazuko_get_value("\nRM=", request->buffer, &value2) != 0)
	{
		call_xp_free(value1);
		return -1;
	}

	did.xp_id = call_xp_id_copy(xp_id);
	did.unique = 0; /* a unique is not yet assigned */

	error = dazuko_register_daemon(&did, value1, dazuko_strlen(value1), dazuko_strchr(value2, 'W') != NULL);

	dazuko_clear_replybuffer(request);
	dazuko_add_keyvalue_to_replybuffer(request, "\nID=", &(did.unique), 'd');
	dazuko_add_keyvalue_to_replybuffer(request, "\nVN=", &VERSION_NUMBER, 's');
	dazuko_add_keyvalue_to_replybuffer(request, "\nVS=", &VERSION_STRING, 's');
	dazuko_close_replybuffer(request);

	call_xp_free(value1);
	call_xp_free(value2);
	call_xp_id_free(did.xp_id);

	return error;
}

static int dazuko_handle_request_basic(struct dazuko_request *request, struct xp_daemon_id *xp_id, int basic_option)
{
	char			*value1;
	int			error = 0;
	struct daemon_id	did;

	/* read "\nID=id" */

	if (request->buffer_size <= 0)
		return -1;

	if (dazuko_get_value("\nID=", request->buffer, &value1) != 0)
		return -1;

	did.xp_id = call_xp_id_copy(xp_id);
	did.unique = dazuko_strtol(value1);

	error = dazuko_set_option(&did, basic_option, NULL, 0);

	call_xp_free(value1);
	call_xp_id_free(did.xp_id);

	return error;
}

static int dazuko_handle_request_set_access_mask(struct dazuko_request *request, struct xp_daemon_id *xp_id)
{
	char			*value1;
	char			*value2;
	int			error = 0;
	struct daemon_id	did;

	/* read "\nID=id\nAM=mask" */

	if (request->buffer_size <= 0)
		return -1;

	if (dazuko_get_value("\nID=", request->buffer, &value1) != 0)
		return -1;

	if (dazuko_get_value("\nAM=", request->buffer, &value2) != 0)
	{
		call_xp_free(value1);
		return -1;
	}

	did.xp_id = call_xp_id_copy(xp_id);
	did.unique = dazuko_strtol(value1);

	error = dazuko_set_option(&did, SET_ACCESS_MASK, value2, dazuko_strlen(value2));

	call_xp_free(value1);
	call_xp_free(value2);
	call_xp_id_free(did.xp_id);

	return error;
}

static int dazuko_handle_request_add_path(struct dazuko_request *request, struct xp_daemon_id *xp_id, int add_path_option)
{
	char			*value1;
	char			*value2;
	int			error = 0;
	struct daemon_id	did;

	/* read "\nID=id\nPT=path" */

	if (request->buffer_size <= 0)
		return -1;

	if (dazuko_get_value("\nID=", request->buffer, &value1) != 0)
		return -1;

	if (dazuko_get_value("\nPT=", request->buffer, &value2) != 0)
	{
		call_xp_free(value1);
		return -1;
	}

	did.xp_id = call_xp_id_copy(xp_id);
	did.unique = dazuko_strtol(value1);

	error = dazuko_set_option(&did, add_path_option, value2, dazuko_strlen(value2));

	call_xp_free(value1);
	call_xp_free(value2);
	call_xp_id_free(did.xp_id);

	return error;
}

static inline int handle_event_as_readonly(struct slot *s)
{
	/* are we in read_only mode? */
	if (!(s->write_mode))
		return 1;

	/* (CLOSE events are treated as read_only since
	 * the action is not implemented as blockable) */

	if (s->event == DAZUKO_ON_CLOSE || s->event == DAZUKO_ON_CLOSE_MODIFIED)
		return 1;

	return 0;
}

static int dazuko_handle_request_get_an_access(struct dazuko_request *request, struct xp_daemon_id *xp_id)
{
	char			*value1;
	int			error = 0;
	struct slot		*s;
	struct daemon_id	did;

	/* read "\nID=id" */
	/* send "\nEV=event\nFN=file\nUI=uid\nPI=pid\nFL=flags\nMD=mode..." */

	if (request->buffer_size <= 0)
		return -1;

	if (request->reply_buffer_size <= 0)
		return -1;

	if (dazuko_get_value("\nID=", request->buffer, &value1) != 0)
		return -1;

	did.xp_id = call_xp_id_copy(xp_id);
	did.unique = dazuko_strtol(value1);

	call_xp_free(value1);

dazuko_handle_request_get_an_access_begin:

/* DOWN? */
	s = dazuko_get_an_access(&did);

	if (s == NULL)
	{
		call_xp_id_free(did.xp_id);
		return XP_ERROR_INTERRUPT;
	}
/* DOWN */

	if (s->dfs != NULL)
	{
		/* Perform filename lookup in this context.
		 * If it fails, we allow the access and
		 * wait for the next access. */

/* XXX: This function will allocate memory. */
		if (call_xp_fill_file_struct(s->dfs) != 0)
		{
			/* failed to lookup filename */

			call_xp_up(&(s->mutex));
/* UP */
			dazuko_return_access(&did, 0, s);
			goto dazuko_handle_request_get_an_access_begin;
		}

		if (!dazuko_is_selected(s->dfs, s->slot_list))
		{
			/* we are not interested in this filename */

			call_xp_up(&(s->mutex));
/* UP */
			dazuko_return_access(&did, 0, s);
			goto dazuko_handle_request_get_an_access_begin;
		}

		memcpy(&(s->file_p), &(s->dfs->file_p), sizeof(struct file_properties));
		s->filename = s->dfs->filename;
		s->filenamelength = s->dfs->filename_length;
	}

	/* Slot IS in DAZUKO_WORKING state. Copy all the
	 * necessary information to userspace structure. */

	dazuko_clear_replybuffer(request);
	dazuko_add_keyvalue_to_replybuffer(request, "\nEV=", &(s->event), 'd');

	if (s->filename != NULL)
		dazuko_add_esc_to_replybuffer(request, "\nFN=", &(s->filename));

	if (s->event_p.set_uid)
		dazuko_add_keyvalue_to_replybuffer(request, "\nUI=", &(s->event_p.uid), 'd');

	if (s->event_p.set_pid)
		dazuko_add_keyvalue_to_replybuffer(request, "\nPI=", &(s->event_p.pid), 'd');

	if (s->event_p.set_flags)
		dazuko_add_keyvalue_to_replybuffer(request, "\nFL=", &(s->event_p.flags), 'd');

	if (s->event_p.set_mode)
		dazuko_add_keyvalue_to_replybuffer(request, "\nMD=", &(s->event_p.mode), 'd');

	if (s->file_p.set_size)
		dazuko_add_keyvalue_to_replybuffer(request, "\nFS=", &(s->file_p.size), 'l');

	if (s->file_p.set_uid)
		dazuko_add_keyvalue_to_replybuffer(request, "\nFU=", &(s->file_p.uid), 'd');

	if (s->file_p.set_gid)
		dazuko_add_keyvalue_to_replybuffer(request, "\nFG=", &(s->file_p.gid), 'd');

	if (s->file_p.set_mode)
		dazuko_add_keyvalue_to_replybuffer(request, "\nFM=", &(s->file_p.mode), 'd');

	if (s->file_p.set_device_type)
		dazuko_add_keyvalue_to_replybuffer(request, "\nDT=", &(s->file_p.device_type), 'd');

	dazuko_close_replybuffer(request);

/* XXX: What do we do if there is a problem copying back to userspace?! */

	if (handle_event_as_readonly(s))
	{
		/* the access is immediately (and at the kernel level)
		 * returned */

		call_xp_up(&(s->mutex));
/* UP */

		dazuko_return_access(&did, 0, s);
	}
	else
	{
		call_xp_up(&(s->mutex));
/* UP */
	}

	call_xp_id_free(did.xp_id);

	return error;
}

static int dazuko_handle_request_return_an_access(struct dazuko_request *request, struct xp_daemon_id *xp_id)
{
	char			*value1;
	char			*value2;
	int			error = 0;
	struct daemon_id	did;
	struct slot		*s;

	/* read "\nID=id\nDN=deny" */

	if (request->buffer_size <= 0)
		return -1;

	if (dazuko_get_value("\nID=", request->buffer, &value1) != 0)
		return -1;

	if (dazuko_get_value("\nDN=", request->buffer, &value2) != 0)
	{
		call_xp_free(value1);
		return -1;
	}

	did.xp_id = call_xp_id_copy(xp_id);
	did.unique = dazuko_strtol(value1);

	/* find our slot */
	s = dazuko_find_slot(&did, 1, NULL);

	if (s == NULL)
	{
		/* It appears the kernel isn't interested
		 * in us or our response. It gave our slot away! */

		DPRINT(("dazuko: daemon %d unexpectedly lost slot (by return access)\n", did.unique));

		error = -1;
	}
	else
	{
		if (!handle_event_as_readonly(s))
			error = dazuko_return_access(&did, dazuko_strtoul(value2), s);
	}

	call_xp_free(value1);
	call_xp_free(value2);
	call_xp_id_free(did.xp_id);

	return error;
}

static int dazuko_handle_request_initialize_cache(struct dazuko_request *request, struct xp_daemon_id *xp_id)
{
	char			*value1;
	char			*value2;
	int			error = 0;
	int			i;
	struct daemon_id	did;

	/* read "\nID=id\nCT=cachettl" */

	if (request->buffer_size <= 0)
		return -1;

	if (dazuko_get_value("\nID=", request->buffer, &value1) != 0)
		return -1;

	if (dazuko_get_value("\nCT=", request->buffer, &value2) != 0)
	{
		call_xp_free(value1);
		return -1;
	}

	did.xp_id = call_xp_id_copy(xp_id);
	did.unique = dazuko_strtol(value1);

	error = dazuko_initialize_cache(&did, dazuko_strtoul(value2));

	call_xp_free(value1);
	call_xp_free(value2);

	if (error)
		i = 0;
	else
		i = 1;

	dazuko_clear_replybuffer(request);
	dazuko_add_keyvalue_to_replybuffer(request, "\nCA=", &i, 'd');
	dazuko_close_replybuffer(request);

	call_xp_id_free(did.xp_id);

	/* the request was successful,
	 * even if a cache is not available */
	return 0;
}

#ifdef TRUSTED_APPLICATION_SUPPORT
static int dazuko_handle_request_register_trusted(struct dazuko_request *request, struct xp_daemon_id *xp_id)
{
	char			*value1;
	char			*value2;
	char			*value3 = NULL;
	int			error = 0;
	int			i;
	struct daemon_id	did;

	/* read "\nGN=group\nTT=token[\nTF=flags]" */
	/* send "\nDN=deny" */

	if (request->buffer_size <= 0)
		return -1;

	if (request->reply_buffer_size <= 0)
		return -1;

	if (dazuko_get_value("\nGN=", request->buffer, &value1) != 0)
		return -1;

	if (dazuko_get_value("\nTT=", request->buffer, &value2) != 0)
	{
		call_xp_free(value1);
		return -1;
	}

	dazuko_get_value("\nTF=", request->buffer, &value3);

	did.xp_id = call_xp_id_copy(xp_id);

	error = dazuko_register_trusted_daemon(did.xp_id, value1, value2, value3);

	if (error)
		i = 1;
	else
		i = 0;

	dazuko_clear_replybuffer(request);
	dazuko_add_keyvalue_to_replybuffer(request, "\nDN=", &i, 'd');
	dazuko_close_replybuffer(request);

	call_xp_free(value1);
	call_xp_free(value2);
	if (value3 != NULL)
		call_xp_free(value3);
	call_xp_id_free(did.xp_id);

	/* the request was successful,
	 * even if a access is denied */
	return 0;
}

static int dazuko_handle_request_remove_trusted(struct dazuko_request *request, struct xp_daemon_id *xp_id)
{
	char			*value1;
	char			*value2;
	int			error = 0;
	struct daemon_id	did;

	/* read "\nID=id\nTT=token" */

	if (request->buffer_size <= 0)
		return -1;

	if (dazuko_get_value("\nID=", request->buffer, &value1) != 0)
		return -1;

	if (dazuko_get_value("\nTT=", request->buffer, &value2) != 0)
	{
		call_xp_free(value1);
		return -1;
	}

	did.xp_id = call_xp_id_copy(xp_id);
	did.unique = dazuko_strtol(value1);

	error = dazuko_set_option(&did, REMOVE_TRUSTED, value2, dazuko_strlen(value2));

	call_xp_free(value1);
	call_xp_free(value2);
	call_xp_id_free(did.xp_id);

	return error;
}

#endif

static int dazuko_handle_request(struct dazuko_request *request, struct xp_daemon_id *xp_id)
{
	int	error = 0;
	int	type;

	if (request == NULL || xp_id == NULL)
		return -1;

	type = request->type[0] + (256 * request->type[1]);

	switch (type)
	{
		case REGISTER:
			return dazuko_handle_request_register(request, xp_id);

		case UNREGISTER:
			return dazuko_handle_request_basic(request, xp_id, type);

		case SET_ACCESS_MASK:
			return dazuko_handle_request_set_access_mask(request, xp_id);

		case ADD_INCLUDE_PATH:
			return dazuko_handle_request_add_path(request, xp_id, type);

		case ADD_EXCLUDE_PATH:
			return dazuko_handle_request_add_path(request, xp_id, type);

		case REMOVE_ALL_PATHS:
			return dazuko_handle_request_basic(request, xp_id, type);

		case GET_AN_ACCESS:
			return dazuko_handle_request_get_an_access(request, xp_id);

		case RETURN_AN_ACCESS:
			return dazuko_handle_request_return_an_access(request, xp_id);

		case INITIALIZE_CACHE:
			return dazuko_handle_request_initialize_cache(request, xp_id);

#ifdef TRUSTED_APPLICATION_SUPPORT
		case REGISTER_TRUSTED:
			return dazuko_handle_request_register_trusted(request, xp_id);

		case UNREGISTER_TRUSTED:
			/* read (nothing) */

			error = dazuko_unregister_trusted_daemon(xp_id);

			break;

		case REMOVE_ALL_TRUSTED:
			return dazuko_handle_request_basic(request, xp_id, type);

		case REMOVE_TRUSTED:
			return dazuko_handle_request_remove_trusted(request, xp_id);
#endif

		default:
			error = XP_ERROR_INVALID;

			break;
	}

	return error;
}

int dazuko_handle_user_request(const char *request_buffer, struct xp_daemon_id *xp_id)
{
	int			error = 0;
	struct dazuko_request	*user_request = NULL;
	unsigned char		*ll_request = NULL;
	unsigned char		*ll_stream = NULL;
	struct dazuko_request	*request = NULL;
	struct dazuko_request	*temp_request = NULL;
	char			*value;
	unsigned char		tempslen[4];
	int			streamlen = 0;

	/*
	 * some notes on the variables: we allocate a "request" struct which
	 * has a kernel space address and references data which is _completely_
	 * valid from within the kernel, in addition we allocate a
	 * "temp_request" struct which has a kernel space address and its data
	 * mirrors the userland struct "user_request", the "ll_stream" byte
	 * array has a kernel space address and holds a copy of the user space
	 * request stream
	 */

	if (request_buffer == NULL || xp_id == NULL)
		return XP_ERROR_FAULT;

	if (dazuko_get_value("\nra=", request_buffer, &value) == 0)
	{
		ll_request = (unsigned char *)dazuko_strtoul(value);
		xp_free(value);
	}
	else if (dazuko_get_value("\nRA=", request_buffer, &value) == 0)
	{
		user_request = (struct dazuko_request *)dazuko_strtoul(value);
		xp_free(value);
	}

	/*
	 * at least one kind of request presentation needs to be given (having
	 * multiple kinds does not hurt -- we pick the most portable one and
	 * process it)
	 */
	if (ll_request == NULL && user_request == NULL)
		return XP_ERROR_FAULT;

	/* allocate temp kernel request */
	temp_request = (struct dazuko_request *)call_xp_malloc(sizeof(struct dazuko_request));
	if (temp_request == NULL)
		return XP_ERROR_FAULT;

	/* allocate kernel request */
	request = (struct dazuko_request *)call_xp_malloc(sizeof(struct dazuko_request));
	if (request == NULL)
	{
		error = XP_ERROR_FAULT;
		goto dazuko_handle_user_request_out;
	}

	/* request bytes are zero'd out because the "out" will check
	 * these values */
	dazuko_bzero(request, sizeof(struct dazuko_request));

	if (ll_request != NULL)
	{
		/*
		 * this is the "new style ra= (streamed) request" -- we have a
		 * description which is high level language independent: fill in *OUR*
		 * C language struct with the data we read in in a portable way
		 */

		/* copy in the length bytes (4 bytes) */
		if (call_xp_copyin(ll_request, tempslen, 4) != 0)
		{
			error = XP_ERROR_FAULT;
			goto dazuko_handle_user_request_out;
		}

		if (dazuko_reqstream_chunksize(tempslen, &streamlen) != 0)
		{
			error = XP_ERROR_FAULT;
			goto dazuko_handle_user_request_out;
		}

		/* allocate a buffer and copyin the stream */
		ll_stream = (unsigned char *)call_xp_malloc(streamlen);
		if (ll_stream == NULL)
		{
			error = XP_ERROR_FAULT;
			goto dazuko_handle_user_request_out;
		}

		if (call_xp_copyin(ll_request, ll_stream, streamlen) != 0)
		{
			error = XP_ERROR_FAULT;
			goto dazuko_handle_user_request_out;
		}

		/* convert the stream to into a (our) struct */
		if (dazuko_reqstream_ll2hl(ll_stream, temp_request, 0) != 0)
		{
			error = XP_ERROR_FAULT;
			goto dazuko_handle_user_request_out;
		}

		/* do NOT release the stream buffer here */
	}
	else if (user_request != NULL)
	{
		/*
		 * this is the "old style (high level language struct) request" -- we
		 * HAVE TO ASSUME that the memory layout of the application and the
		 * kernel module match regarding the "struct dazuko_request" data type
		 * (yes, it's dangerous but we have no means to check anything here)
		 */

		/* copy in the request */
		if (call_xp_copyin(user_request, temp_request, sizeof(struct dazuko_request)) != 0)
		{
			error = XP_ERROR_FAULT;
			goto dazuko_handle_user_request_out;
		}
	}

	/*
	 * at this point we have a valid request structure in "temp_request"
	 * (still pointing to userland buffers for request and reply)
	 */

	memcpy(request->type, temp_request->type, sizeof(char[2]));

	/* sanity check */
	request->buffer_size = temp_request->buffer_size;
	if (request->buffer_size < 0 || request->buffer_size > 8192)
	{
		error = XP_ERROR_FAULT;
		goto dazuko_handle_user_request_out;
	}

	/* sanity check */
	request->reply_buffer_size = temp_request->reply_buffer_size;
	if (request->reply_buffer_size < 0 || request->reply_buffer_size > 8192)
	{
		error = XP_ERROR_PERMISSION;
		goto dazuko_handle_user_request_out;
	}

	if (request->buffer_size > 0)
	{
		/* allocate request command string buffer */
		request->buffer = (char *)call_xp_malloc(request->buffer_size + 1);
		if (request->buffer == NULL)
		{
			error = XP_ERROR_FAULT;
			goto dazuko_handle_user_request_out;
		}

	}

	if (request->reply_buffer_size > 0)
	{
		/* allocate reply text buffer */
		request->reply_buffer = (char *)call_xp_malloc(request->reply_buffer_size + 1);
		if (request->reply_buffer == NULL)
		{
			error = XP_ERROR_FAULT;
			goto dazuko_handle_user_request_out;
		}

		request->reply_buffer_size_used = 0;
	}

	if (request->buffer_size > 0)
	{
		/* copy the buffer from userspace to kernelspace */
		if (call_xp_copyin(temp_request->buffer, request->buffer, request->buffer_size) != 0)
		{
			error = XP_ERROR_FAULT;
			goto dazuko_handle_user_request_out;
		}

		request->buffer[request->buffer_size] = 0;
	}

	/* process the request */
	error = dazuko_handle_request(request, xp_id);

	/* successfully processed and a response to be transferred back? */
	if (error == 0 && request->reply_buffer_size > 0)
	{
		request->reply_buffer[request->reply_buffer_size] = 0;

		temp_request->reply_buffer_size_used = request->reply_buffer_size_used;

		if (ll_request != NULL)
		{
			/* new style (streamed) request */

			/* update a few return fields */
			if (dazuko_reqstream_updll(temp_request, ll_stream) != 0)
			{
				error = XP_ERROR_FAULT;
				goto dazuko_handle_user_request_out;
			}

			/* copyout the stream back to the application */
			if (call_xp_copyout(ll_stream, ll_request, streamlen) != 0)
			{
				error = XP_ERROR_FAULT;
				goto dazuko_handle_user_request_out;
			}
		}
		else if (user_request != NULL)
		{
			/* old style (high level language struct) request */

			/* copyout the complete "struct dazuko_request" struct */
			if (call_xp_copyout(temp_request, user_request, sizeof(struct dazuko_request)) != 0)
			{
				error = XP_ERROR_FAULT;
				goto dazuko_handle_user_request_out;
			}
		}

		/* transfer back the reply data itself */
		if (request->reply_buffer_size_used > 0)
		{
			/* reply_buffer_size_used already includes the NUL byte */
			if (call_xp_copyout(request->reply_buffer, temp_request->reply_buffer, request->reply_buffer_size_used) != 0)
			{
				error = XP_ERROR_FAULT;
				goto dazuko_handle_user_request_out;
			}
		}
	}

dazuko_handle_user_request_out:

	if (request != NULL)
	{
		if (request->buffer != NULL)
			call_xp_free(request->buffer);

		if (request->reply_buffer != NULL)
			call_xp_free(request->reply_buffer);

		call_xp_free(request);
	}

	if (temp_request != NULL)
		call_xp_free(temp_request);

	if (ll_stream != NULL)
		call_xp_free(ll_stream);

	return error;
}

int dazuko_handle_user_request_compat1(void *ptr, int cmd, struct xp_daemon_id *xp_id)
{
	struct access_compat1	*user_request_1;
	struct access_compat1	*temp_request_1;
	struct slot_list	*sl;
	int			error = 0;
	struct slot		*s;
	char			*k_param;
	struct daemon_id	did;
	int			temp_length;
	int			temp_int;

	if (ptr == NULL || xp_id == NULL)
		return XP_ERROR_FAULT;

	did.xp_id = call_xp_id_copy(xp_id);
	did.unique = -1;

	switch (cmd)
	{
		case IOCTL_GET_AN_ACCESS:
			/* The daemon is requesting a filename of a file
			 * to scan. This code will wait until a filename
			 * is available, or until we should be killed.
			 * (killing is done if any errors occur as well
			 * as when the user kills us) */

			user_request_1 = (struct access_compat1 *)ptr;

			error = call_xp_verify_user_writable(user_request_1, sizeof(struct access_compat1));
			if (error)
			{
				error = XP_ERROR_FAULT;
				break;
			}

/* DOWN? */
			s = dazuko_get_an_access(&did);

			if (s == NULL)
			{
				error = XP_ERROR_INTERRUPT;
				break;
			}

/* DOWN */

			/* Slot IS in WORKING state. Copy all the
			 * necessary information to userspace structure. */

			if (s->filenamelength >= DAZUKO_FILENAME_MAX_LENGTH_COMPAT1)
			{
				/* filename length overflow :( */

				s->filename[DAZUKO_FILENAME_MAX_LENGTH_COMPAT1 - 1] = 0;
				temp_length = DAZUKO_FILENAME_MAX_LENGTH_COMPAT1;
			}
			else
			{
				temp_length = s->filenamelength + 1;
			}

			temp_request_1 = (struct access_compat1 *)call_xp_malloc(sizeof(struct access_compat1));
			if (temp_request_1 == NULL)
			{
				error = XP_ERROR_FAULT;
			}
			else if (call_xp_copyin(user_request_1, temp_request_1, sizeof(struct access_compat1)) != 0)
			{
				error = XP_ERROR_FAULT;
			}

			if (error == 0)
			{
				temp_request_1->event = s->event;
				temp_request_1->o_flags = s->event_p.flags;
				temp_request_1->o_mode = s->event_p.mode;
				temp_request_1->uid = s->event_p.uid;
				temp_request_1->pid = s->event_p.pid;
				memcpy(temp_request_1->filename, s->filename, temp_length);

				if (call_xp_copyout(temp_request_1, user_request_1, sizeof(struct access_compat1)) != 0)
				{
					error = XP_ERROR_FAULT;
				}
			}

			call_xp_up(&(s->mutex));
/* UP */

			if (error)
			{
				if (dazuko_change_slot_state(s, DAZUKO_WORKING, DAZUKO_BROKEN, 1))
				{
					/* slot->state has changed to BROKEN, notifiy appropriate queue */
					call_xp_notify(&(s->wait_kernel_waiting_until_this_slot_not_WAITING_and_not_WORKING));
				}
			}

			if (temp_request_1 != NULL)
			{
				call_xp_free(temp_request_1);
			}

			break;

		case IOCTL_RETURN_ACCESS:
			/* The daemon has finished scanning a file
			 * and has the response to give. The daemon's
			 * slot should be in the WORKING state. */

			user_request_1 = (struct access_compat1 *)ptr;

			error = call_xp_verify_user_readable(user_request_1, sizeof(struct access_compat1));
			if (error)
			{
				error = XP_ERROR_FAULT;
				break;
			}

			temp_request_1 = (struct access_compat1 *)call_xp_malloc(sizeof(struct access_compat1));
			if (temp_request_1 == NULL)
			{
				error = XP_ERROR_FAULT;
				break;
			}

			if (call_xp_copyin(user_request_1, temp_request_1, sizeof(struct access_compat1)) != 0)
			{
				error = XP_ERROR_FAULT;
			}

			temp_int = temp_request_1->deny;

			call_xp_free(temp_request_1);

			/* find our slot */
			s = dazuko_find_slot(&did, 1, NULL);

			if (s == NULL)
			{
				/* It appears the kernel isn't interested
				 * in us or our response. It gave our slot away! */

				DPRINT(("dazuko: daemon %d unexpectedly lost slot (by return access compat1)\n", did.unique));

				error = XP_ERROR_FAULT;
			}
			else if (!handle_event_as_readonly(s))
			{
				error = dazuko_return_access(&did, temp_int, s);
			}

			break;

		case IOCTL_SET_OPTION:
			/* The daemon wants to set a configuration
			 * option in the kernel. */

			error = call_xp_verify_user_readable(ptr, 2*sizeof(int));
			if (error)
			{
				error = XP_ERROR_FAULT;
				break;
			}

			/* copy option type from userspace */
			if (call_xp_copyin(ptr, &temp_int, sizeof(int)) != 0)
			{
				error = XP_ERROR_FAULT;
				break;
			}

			ptr = ((char *)ptr + sizeof(int));

			/* copy path length from userspace */
			if (call_xp_copyin(ptr, &temp_length, sizeof(int)) != 0)
			{
				error = XP_ERROR_FAULT;
				break;
			}

			/* sanity check */
			if (temp_length < 0 || temp_length > 4096)
			{
				error = XP_ERROR_INVALID;
				break;
			}

			ptr = ((char *)ptr + sizeof(int));

			error = call_xp_verify_user_readable(ptr, temp_length);
			if (error)
			{
				error = XP_ERROR_FAULT;
				break;
			}

			k_param = (char *)call_xp_malloc(temp_length + 1);
			if (k_param == NULL)
			{
				error = XP_ERROR_FAULT;
				break;
			}

			/* We must copy the param from userspace to kernelspace. */

			if (call_xp_copyin(ptr, k_param, temp_length) != 0)
			{
				call_xp_free(k_param);
				error = XP_ERROR_FAULT;
				break;
			}

			k_param[temp_length] = 0;

			switch (temp_int)
			{
				case REGISTER:
					error = dazuko_register_daemon(&did, k_param, temp_length, 1);
					break;

				case SET_ACCESS_MASK:
					/* find our slot */
					if (dazuko_find_slot_and_slotlist(&did, 1, NULL, &sl) == NULL)
					{
						error = XP_ERROR_PERMISSION;
					}
					else if (sl == NULL)
					{
						error = XP_ERROR_PERMISSION;
					}
					else
					{
						sl->access_mask = k_param[0];

						/* rebuild access_mask_cache */
						dazuko_setup_amc_cache();
					}
					break;

				default:
					error = dazuko_set_option(&did, temp_int, k_param, temp_length);
					break;
			}

			call_xp_free(k_param);

			break;

		default:
			error = XP_ERROR_INVALID;

			break;
	}

	call_xp_id_free(did.xp_id);

	return error;
}

int dazuko_check_access(unsigned long event, int daemon_is_allowed, struct xp_daemon_id *xp_id, struct slot_list **cached_lookup)
{	
	int			i;
	struct slot_list	*sl = NULL;

	/* do we have any daemons? */
	if (call_xp_atomic_read(&active) <= 0)
		return -1;

	/* is a group interested in this event type? */

	i = dazuko_event2index(event);
	if (i < 0 || i >= NUM_EVENTS)
		return -1;

/* DOWN */
	call_xp_down(&mutex_amc);

	i = access_mask_cache[i][0];

	call_xp_up(&mutex_amc);
/* UP */

	if (i == AMC_UNSET)
		return -1;

	if (dazuko_is_our_daemon(xp_id, &sl, NULL))
	{
		/* should daemons be allowed this event without a scan? */
		if (daemon_is_allowed)
		{
			/* this is one of our daemons, so we will report as
			 * as if this event was not in the mask */

			return -1;
		}
		else
		{
			/* this is one of our daemons, but the
			 * other groups must be informed */

			/* if there are no other groups, allow this event */
			if (call_xp_atomic_read(&groupcount) == 1)
				return -1;

			if (cached_lookup != NULL)
			{
				/* this slot list (ours) will be skipped */
				*cached_lookup = sl;
			}
		}
	}

	/* if we made it this far, then the
	 * access should be processed */

	return 0;
}

int dazuko_process_access(unsigned long event, struct dazuko_file_struct *kfs, struct event_properties *event_p, struct slot_list *cached_lookup)
{
	/* return codes:
	 *   >0 -> access should be blocked
	 *   <0 -> access should be blocked (because user interrupted)
	 *    0 -> access is allowed
	 */

	int		error = 0;

	if (kfs == NULL)
	{
		/* kfs is required */

		call_xp_print("dazuko: kfs=NULL (possible bug)\n");

		return XP_ERROR_PERMISSION;
	}

	/* check and handle this event */
	error = dazuko_run_daemon(event, kfs, event_p, cached_lookup);

	if (error > 0)
	{
		/* access will be blocked */

		return XP_ERROR_PERMISSION;
	}
	else if (error < 0)
	{
		/* user interrupted */

		return XP_ERROR_INTERRUPT;
	}

	/* access allowed */

	return 0;
}

int dazuko_init(void)
{
	int	i;
	int	error;

	call_xp_init_mutex(&mutex_unique_count);
	call_xp_init_mutex(&mutex_amc);

	dazuko_bzero(&slot_lists, sizeof(slot_lists));

	memset(&access_mask_cache, AMC_UNSET, sizeof(access_mask_cache));

	for (i=0 ; i<NUM_SLOT_LISTS ; i++)
		call_xp_init_mutex(&(slot_lists[i].mutex));

	call_xp_atomic_set(&active, 0);
	call_xp_atomic_set(&groupcount, 0);

	error = call_xp_sys_hook();

	if (error == 0)
		call_xp_print("dazuko: loaded, version=%s\n", VERSION_STRING);

  	return error;
}

int dazuko_exit(void)
{
	int	error;
	int	i;
	int	j;

	i = call_xp_atomic_read(&active);

	if (i != 0)
	{
		call_xp_print("dazuko: warning: trying to remove Dazuko with %d process%s still registered\n", i, i==1 ? "" : "es");
		return -1;
	}

	error = call_xp_sys_unhook();

	if (error == 0)
	{
		call_xp_destroy_mutex(&mutex_unique_count);
		call_xp_destroy_mutex(&mutex_amc);

		for (i=0 ; i<NUM_SLOT_LISTS ; i++)
		{
			if (slot_lists[i].slot_list != NULL)
			{
				dazuko_remove_all_paths(slot_lists[i].slot_list);

				if (call_xp_atomic_read(&(slot_lists[i].slot_list->use_count)) != 0)
					call_xp_print("dazuko: slot_list count was not 0 (possible bug)\n");

				for (j=0 ; j<NUM_SLOTS ; j++)
				{
					call_xp_destroy_mutex(&(slot_lists[i].slot_list->slots[j].mutex));
					call_xp_destroy_queue(&(slot_lists[i].slot_list->slots[j].wait_daemon_waiting_until_this_slot_not_READY));
					call_xp_destroy_queue(&(slot_lists[i].slot_list->slots[j].wait_kernel_waiting_until_this_slot_not_WAITING_and_not_WORKING));
					call_xp_destroy_queue(&(slot_lists[i].slot_list->slots[j].wait_daemon_waiting_until_this_slot_not_DONE));
				}

				call_xp_destroy_rwlock(&(slot_lists[i].slot_list->lock_lists));

#ifdef TRUSTED_APPLICATION_SUPPORT
				dazuko_remove_all_trusted(slot_lists[i].slot_list);
				call_xp_destroy_rwlock(&(slot_lists[i].slot_list->lock_trusted_list));
#endif

				call_xp_destroy_queue(&(slot_lists[i].slot_list->wait_kernel_waiting_for_any_READY_slot_or_zero_use_count));

				if (slot_lists[i].slot_list->reg_name != NULL)
					call_xp_free(slot_lists[i].slot_list->reg_name);
				slot_lists[i].slot_list->reg_name = NULL;

				call_xp_free(slot_lists[i].slot_list);
				slot_lists[i].slot_list = NULL;
			}

			call_xp_destroy_mutex(&(slot_lists[i].mutex));
		}

		call_xp_print("dazuko: unloaded, version=%s\n", VERSION_STRING);
	}

	return error;
}
