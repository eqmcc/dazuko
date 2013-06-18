/* Dazuko Dummy. A dummy implementation to help porting to new platforms.
   Written by John Ogness <dazukocode@ogness.net>

   Copyright (c) 2004, 2005 H+BEDV Datentechnik GmbH
   Copyright (c) 2007 Avira GmbH
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


#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "dazuko_dummyos.h"
#include "dazuko_core.h"


struct daemon_thread
{
	pthread_t		thread;
	int			fd;
	struct daemon_thread	*next;
};

#if defined(ON_OPEN_SUPPORT)
static int dummy_dazuko_sys_open(const char *filename);
#endif

#if defined(ON_CLOSE_SUPPORT) || defined(ON_CLOSE_MODIFIED_SUPPORT)
static int dummy_dazuko_sys_close(const char *filename);
#endif

#ifdef ON_EXEC_SUPPORT
static int dummy_dazuko_sys_execve(const char *filename);
#endif

#ifdef ON_UNLINK_SUPPORT
static int dummy_dazuko_sys_unlink(const char *filename);
#endif

#ifdef ON_RMDIR_SUPPORT
static int dummy_dazuko_sys_rmdir(const char *filename);
#endif


static pthread_t		acceptor_id;
static int			acceptor_fd = -1;
static struct daemon_thread	*daemon_list = NULL;
static int			DUMMY_ID = 0;


/* mutex */

void xp_init_mutex(struct xp_mutex *mutex)
{
	pthread_mutex_init(&(mutex->mutex), NULL);
}

void xp_down(struct xp_mutex *mutex)
{
	pthread_mutex_lock(&(mutex->mutex));
}

void xp_up(struct xp_mutex *mutex)
{
	pthread_mutex_unlock(&(mutex->mutex));
}

void xp_destroy_mutex(struct xp_mutex *mutex)
{
	pthread_mutex_destroy(&(mutex->mutex));
}


/* read-write lock */

void xp_init_rwlock(struct xp_rwlock *rwlock)
{
	pthread_mutex_init(&(rwlock->rwlock), NULL);
}

void xp_write_lock(struct xp_rwlock *rwlock)
{
	pthread_mutex_lock(&(rwlock->rwlock));
}

void xp_write_unlock(struct xp_rwlock *rwlock)
{
	pthread_mutex_unlock(&(rwlock->rwlock));
}

void xp_read_lock(struct xp_rwlock *rlock)
{
	pthread_mutex_lock(&(rlock->rwlock));
}

void xp_read_unlock(struct xp_rwlock *rlock)
{
	pthread_mutex_unlock(&(rlock->rwlock));
}

void xp_destroy_rwlock(struct xp_rwlock *rwlock)
{
	pthread_mutex_destroy(&(rwlock->rwlock));
}


/* wait-notify queue */

int xp_init_queue(struct xp_queue *queue)
{
	pthread_cond_init(&(queue->condition), NULL);
	pthread_mutex_init(&(queue->mutex), NULL);

	return 0;
}

int xp_wait_until_condition(struct xp_queue *queue, int (*cfunction)(void *), void *cparam, int allow_interrupt)
{
	pthread_mutex_lock(&(queue->mutex));

	while (1)
	{
		if (cfunction(cparam))
			break;

		pthread_cond_wait(&(queue->condition), &(queue->mutex));
	}

	pthread_mutex_unlock(&(queue->mutex));

	return 0;
}

int xp_notify(struct xp_queue *queue)
{
	pthread_cond_broadcast(&(queue->condition));

	return 0;
}

int xp_destroy_queue(struct xp_queue *queue)
{
	pthread_cond_destroy(&(queue->condition));
	pthread_mutex_destroy(&(queue->mutex));

	return 0;
}


/* memory */

void* xp_malloc(size_t size)
{
	return malloc(size);
}

int xp_free(void *ptr)
{
	free(ptr);

	return 0;
}

int xp_copyin(const void *user_src, void *kernel_dest, size_t size)
{
	memcpy(kernel_dest, user_src, size);

	return 0;
}

int xp_copyout(const void *kernel_src, void *user_dest, size_t size)
{
	memcpy(user_dest, kernel_src, size);

	return 0;
}

int xp_verify_user_writable(const void *user_ptr, size_t size)
{
	return 0;
}

int xp_verify_user_readable(const void *user_ptr, size_t size)
{
	return 0;
}


/* path attribute */

int xp_is_absolute_path(const char *path)
{
	return (path[0] == '/');
}


/* atomic */

int xp_atomic_set(struct xp_atomic *atomic, int value)
{
	atomic->atomic = value;

	return 0;
}

int xp_atomic_inc(struct xp_atomic *atomic)
{
	(atomic->atomic)++;

	return 0;
}

int xp_atomic_dec(struct xp_atomic *atomic)
{
	(atomic->atomic)--;

	return 0;
}

int xp_atomic_read(struct xp_atomic *atomic)
{
	return atomic->atomic;
}


/* file structure */

int xp_fill_file_struct(struct dazuko_file_struct *dfs)
{
	int	length;

	length = strlen(dfs->extra_data->user_filename);

	dfs->filename = (char *)xp_malloc(length + 1);
	if (dfs->filename != NULL)
	{
		memcpy(dfs->filename, dfs->extra_data->user_filename, length);
		dfs->filename[length] = 0;
		dfs->filename_length = length;  /* the string length */
	}

	return 0;
}

static int dazuko_file_struct_cleanup(struct dazuko_file_struct **dfs)
{
	if (dfs == NULL)
		return 0;

	if (*dfs == NULL)
		return 0;

	if ((*dfs)->filename)
		xp_free((*dfs)->filename);

	if ((*dfs)->extra_data)
		xp_free((*dfs)->extra_data);

	xp_free(*dfs);

	*dfs = NULL;

	return 0;
}


/* daemon id */

int xp_id_compare(struct xp_daemon_id *id1, struct xp_daemon_id *id2, int check_related)
{
	if (id1 == NULL || id2 == NULL)
		return DAZUKO_DIFFERENT;

	if (id1->id == id2->id)
		return DAZUKO_SAME;

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
		ptr->id = id->id;

	return ptr;
}


/* event */

int xp_set_event_properties(struct event_properties *event_p, struct xp_daemon_id *xp_id)
{
	event_p->pid = xp_id->id;
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

static void dummy_dazuko_setid(const char *id)
{
	DUMMY_ID = atoi(id);
}

static int dummy_dazuko_sys_generic(int event, const char *filename, int daemon_is_allowed)
{
	struct dazuko_file_struct	*dfs = NULL;
	struct event_properties		event_p;
	struct xp_daemon_id		xp_id;
	int				error = 0;
	int				check_error = 0;
	struct slot_list		*sl = NULL;

	xp_id.id = DUMMY_ID;
	check_error = dazuko_check_access(event, daemon_is_allowed, &xp_id, &sl);

	if (check_error == 0)
	{
		dazuko_bzero(&event_p, sizeof(event_p));
		event_p.pid = xp_id.id;
		event_p.set_pid = 1;
		event_p.uid = 15;
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

#ifdef ON_OPEN_SUPPORT
static int dummy_dazuko_sys_open(const char *filename)
{
	int	error;

	error = dummy_dazuko_sys_generic(DAZUKO_ON_OPEN, filename, 1);

	if (error)
		return error;

	/* call the standard openn function */
	printf("dazuko: calling sys_open(\"%s\")\n", filename);

	/* return the return value of the standard exec function */
	return 0;
}
#endif

#if defined(ON_CLOSE_SUPPORT) || defined(ON_CLOSE_MODIFIED)
static int dummy_dazuko_sys_close(const char *filename)
{
	/* call the standard openn function */
	printf("dazuko: calling sys_close(\"%s\")\n", filename);

	dummy_dazuko_sys_generic(DAZUKO_ON_CLOSE, filename, 1);

	/* return the return value of the standard exec function */
	return 0;
}
#endif

#ifdef ON_EXEC_SUPPORT
static int dummy_dazuko_sys_execve(const char *filename)
{
	int	error;

	error = dummy_dazuko_sys_generic(DAZUKO_ON_EXEC, filename, 0);

	if (error)
		return error;

	/* call the standard exec function */
	printf("dazuko: calling sys_exec(\"%s\")\n", filename);

	/* return the return value of the standard exec function */
	return 0;
}
#endif

#ifdef ON_UNLINK_SUPPORT
static int dummy_dazuko_sys_unlink(const char *filename)
{
	int	error;

	error = dummy_dazuko_sys_generic(DAZUKO_ON_UNLINK, filename, 1);

	if (error)
		return error;

	/* call the standard unlink function */
	printf("dazuko: calling sys_unlink(\"%s\")\n", filename);

	/* return the return value of the standard unlink function */
	return 0;
}
#endif

#ifdef ON_RMDIR_SUPPORT
static int dummy_dazuko_sys_rmdir(const char *filename)
{
	int	error;

	error = dummy_dazuko_sys_generic(DAZUKO_ON_RMDIR, filename, 1);

	if (error)
		return error;

	/* call the standard rmdir function */
	printf("dazuko: calling sys_rmdir(\"%s\")\n", filename);

	/* return the return value of the standard rmdir function */
	return 0;
}
#endif


/* system hook */

static int fullread(int fd, void *buf, size_t nbytes)
{
	int	rc;
	size_t	pbytes = 0;

	do
	{
		rc = read(fd, buf + pbytes, nbytes - pbytes);

		if (rc <= 0)
			return -1;

		pbytes += rc;
	}
	while (pbytes < nbytes);

	return 0;
}

static int fullwrite(int fd, void *buf, size_t nbytes)
{
	int	rc;
	size_t	pbytes = 0;

	do
	{
		rc = write(fd, buf + pbytes, nbytes - pbytes);

		if (rc < 0)
			return -1;

		pbytes += rc;
	}
	while (pbytes < nbytes);

	return 0;
}

static void* daemon_main(void *param)
{
	struct daemon_thread	*dt;
	struct dazuko_request	request;
	char reqdesc[64];
	long long ptr_num;
	struct xp_daemon_id	xp_id;

	dt = (struct daemon_thread *)param;

	while (1)
	{
		if (fullread(dt->fd, &request, sizeof(request)) != 0)
			break;

		request.buffer = NULL;
		request.reply_buffer = NULL;

		if (request.buffer_size > 0)
		{
			request.buffer = (char *)malloc(request.buffer_size);
			if (request.buffer == NULL)
				break;

			if (fullread(dt->fd, request.buffer, request.buffer_size) != 0)
				break;
		}

		if (request.reply_buffer_size > 0)
		{
			request.reply_buffer = (char *)malloc(request.reply_buffer_size);
			if (request.reply_buffer == NULL)
				break;

			if (fullread(dt->fd, request.reply_buffer, request.reply_buffer_size) != 0)
				break;
		}

		/* we now have the full request from the daemon */

		xp_id.id = dt->fd;

		memset(reqdesc, 0, sizeof(reqdesc));
		snprintf(reqdesc, sizeof(reqdesc), "%p", &request);
		ptr_num = strtoll(reqdesc, NULL, 16);
		snprintf(reqdesc, sizeof(reqdesc), "\nRA=%lld", (long long)ptr_num);
		if (dazuko_handle_user_request(reqdesc, &xp_id) != 0)
			break;

		/* we now have the request response */

		if (fullwrite(dt->fd, &request, sizeof(request)) != 0)
			break;

		if (request.buffer_size > 0)
		{
			if (fullwrite(dt->fd, request.buffer, request.buffer_size) != 0)
				break;
		}

		if (request.reply_buffer_size > 0)
		{
			if (fullwrite(dt->fd, request.reply_buffer, request.reply_buffer_size) != 0)
				break;
		}

		if (request.buffer != NULL)
			free(request.buffer);

		if (request.reply_buffer != NULL)
			free(request.reply_buffer);
	}

	close(dt->fd);

	return NULL;
}

static void* acceptor_main(void *param)
{
	int			fd;
	struct daemon_thread	*dt;

	while (1)
	{
		fd = accept(acceptor_fd, NULL, NULL);

		if (fd < 0)
			break;

		dt = (struct daemon_thread *)malloc(sizeof(struct daemon_thread));
		if (dt == NULL)
		{
			close(fd);
		}
		else
		{
			dt->fd = fd;
			dt->next = daemon_list;
			daemon_list = dt;

			/* start the "daemon" thread */
			pthread_create(&(dt->thread), NULL, daemon_main, dt);
		}
	}

	while (daemon_list != NULL)
	{
		pthread_join(daemon_list->thread, NULL);
		dt = daemon_list;
		daemon_list = daemon_list->next;
		free(dt);
	}

	return NULL;
}

int xp_sys_hook()
{
	struct sockaddr_in	sa;
	int			i;

	printf("dazuko: setting up communication for daemons\n");

	acceptor_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (acceptor_fd < 0)
		return -1;

	i = 1;
	setsockopt(acceptor_fd, SOL_SOCKET, SO_REUSEADDR, (void *)&i, sizeof(i));

	memset(&sa, 0, sizeof(struct sockaddr_in));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(61234);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (bind(acceptor_fd, (struct sockaddr *)&sa, sizeof(sa)) != 0)
	{
		close(acceptor_fd);
		return -1;
	}

	if (listen(acceptor_fd, 10) != 0)
	{
		close(acceptor_fd);
		return -1;
	}

	/* start the "acceptor" thread */
	pthread_create(&acceptor_id, NULL, acceptor_main, NULL);

	printf("dazuko: hooking file access calls\n");

	return 0;
}

int xp_sys_unhook()
{
	printf("dazuko: unhooking file access calls\n");

	printf("dazuko: closing communication for daemons\n");

	close(acceptor_fd);

	pthread_join(acceptor_id, NULL);

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


/* init/exit */

/* used for generating access events from the keyboard */
static int readinput()
{
	char line[256];
	char *p;

	if (fgets(line, sizeof(line), stdin) == NULL)
		return -1;

	p = strchr(line, 10);
	if (p != NULL)
		*p = 0;

	p = strchr(line, 13);
	if (p != NULL)
		*p = 0;

	if (strcmp(line, "quit") == 0)
	{
		if (dazuko_exit() == 0)
		{
			return -1;
		}
	}
	else if (strncmp(line, "setid ", 6) == 0)
	{
		dummy_dazuko_setid(line + 6);
	}
#ifdef ON_OPEN_SUPPORT
	else if (strncmp(line, "open ", 5) == 0)
	{
		dummy_dazuko_sys_open(line + 5);
	}
#endif
#if defined(ON_CLOSE_SUPPORT) || defined(ON_CLOSE_MODIFIED)
	else if (strncmp(line, "close ", 6) == 0)
	{
		dummy_dazuko_sys_close(line + 6);
	}
#endif
#ifdef ON_EXEC_SUPPORT
	else if (strncmp(line, "exec ", 5) == 0)
	{
		dummy_dazuko_sys_execve(line + 5);
	}
#endif
#ifdef ON_UNLINK_SUPPORT
	else if (strncmp(line, "unlink ", 7) == 0)
	{
		dummy_dazuko_sys_unlink(line + 7);
	}
#endif
#ifdef ON_RMDIR_SUPPORT
	else if (strncmp(line, "rmdir ", 6) == 0)
	{
		dummy_dazuko_sys_rmdir(line + 6);
	}
#endif
	else
	{
		printf("commands:\n");
#ifdef ON_OPEN_SUPPORT
		printf("    open <filename>\n");
#endif
#if defined(ON_CLOSE_SUPPORT) || defined(ON_CLOSE_MODIFIED)
		printf("    close <filename>\n");
#endif
#ifdef ON_EXEC_SUPPORT
		printf("    exec <filename>\n");
#endif
#ifdef ON_UNLINK_SUPPORT
		printf("    unlink <filename>\n");
#endif
#ifdef ON_RMDIR_SUPPORT
		printf("    rmdir <filename>\n");
#endif
		printf("    quit\n");
	}

	return 0;
}

int main()
{
	if (dazuko_init() == 0)
	{
		/* read from keyboard */
		do
		{
			printf("DummyOS kernel> ");
			fflush(stdout);
		}
		while (readinput() == 0);
	}

	return 0;
}

