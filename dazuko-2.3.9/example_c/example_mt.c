/* Example program demonstrating the capabilities/interface of Dazuko.
   Written by John Ogness <dazukocode@ogness.net>

   Copyright (c) 2003, 2004, 2005 H+BEDV Datentechnik GmbH
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

/* This program is a simple application demonstrating how to interface
   with Dazuko. The program instructs Dazuko to detect all types of
   accesses within the specified directories (or any subdirectory
   thereof). The program than prints out the accesses and instructs
   Dazuko to allow access.

   This program will run only after Dazuko has been successfully installed.
   Please see the Dazuko website for information on how to do this.
   http://www.dazuko.org
*/

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include "dazukoio.h"

struct main_loop_struct
{
	int	argc;
	char	**argv;
	int	thread_id;
};

#define NUMBER_OF_THREADS 5

int			RUNNING = 1;		/* flag for main loop */
struct main_loop_struct	id[NUMBER_OF_THREADS]; 	/* id's for threads */

void print_usage(void)
{
	printf("usage: example <dir> <dir> ...\n");
}

void sigterm(int sig)
{
	/* exit the loop on TERM or INT signal */

	RUNNING = 0;
	signal(sig, sigterm);
}

void print_access(struct dazuko_access *acc, int thread_id)
{
	/* print access data */

	if (!acc->set_event)
		return;

	switch (acc->event)
	{
		case DAZUKO_ON_OPEN:
			printf("OPEN  ");
			break;
		case DAZUKO_ON_CLOSE:
			printf("CLOSE ");
			break;
		case DAZUKO_ON_CLOSE_MODIFIED:
			printf("CLOSE (modified)");
			break;
		case DAZUKO_ON_EXEC:
			printf("EXEC  ");
			break;
		case DAZUKO_ON_UNLINK:
			printf("UNLINK");
			break;
		case DAZUKO_ON_RMDIR:
			printf("RMDIR ");
			break;
		default:
			printf("????   event:%d ", acc->event);
			break;
	}

	if (acc->set_uid)
		printf(" uid:%d", acc->uid);

	if (acc->set_pid)
		printf(" pid:%d", acc->pid);

	if (acc->set_mode)
		printf(" mode:%d", acc->mode);

	if (acc->set_flags)
		printf(" flags:%d", acc->flags);

	if (acc->set_file_uid)
		printf(" file_uid:%d", acc->file_uid);

	if (acc->set_file_gid)
		printf(" file_gid:%d", acc->file_gid);

	if (acc->set_file_mode)
		printf(" file_mode:%d", acc->file_mode);

	if (acc->set_file_device)
		printf(" file_device:%d", acc->file_device);

	if (acc->set_file_size)
		printf(" file_size:%lu", acc->file_size);

	if (acc->set_filename)
		printf(" file:%s", acc->filename);

	printf("(thread:%d)", thread_id);

	printf("\n");

	fflush(stdout);
}

void* main_loop(void *param)
{
	dazuko_id_t		*dazuko_id;
	struct dazuko_access	*acc;
	int			thread_id = 0;
	int			args_ok = 0;
	int			i;
	int			argc;
	char			**argv;
	sigset_t		sigset;

	if (param == NULL)
	{
		printf("error: invalid thread parameter\n");
		return NULL;
	}

	/* ignore SIGINT and SIGTERM within threads */
	if (sigemptyset(&sigset) == 0)
	{
		sigaddset(&sigset, SIGINT);
		sigaddset(&sigset, SIGTERM);
		pthread_sigmask(SIG_BLOCK, &sigset, NULL);
	}

	/* catch SIGUSR1 within threads */
	if (sigemptyset(&sigset) == 0)
	{
		sigaddset(&sigset, SIGUSR1);
		pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);
	}

	argc = ((struct main_loop_struct *)param)->argc;
	argv = ((struct main_loop_struct *)param)->argv;
	thread_id = ((struct main_loop_struct *)param)->thread_id;

	/* register with dazuko */
	if (dazukoRegister_TS(&dazuko_id, "DAZUKO_EXAMPLE", "r+") != 0)
	{
		printf("error: failed to register with Dazuko (thread:%d)\n", thread_id);
		return NULL;
	}

	printf("registered with Dazuko successfully (thread:%d)\n", thread_id);

	/* detect TERM signals */
	signal(SIGTERM, sigterm);

	/* detect INT signals */
	signal(SIGINT, sigterm);

	/* set access mask */
	if (dazukoSetAccessMask_TS(dazuko_id, DAZUKO_ON_OPEN | DAZUKO_ON_CLOSE | DAZUKO_ON_CLOSE_MODIFIED | DAZUKO_ON_EXEC | DAZUKO_ON_UNLINK | DAZUKO_ON_RMDIR) != 0)
	{
		printf("error: failed to set access mask (thread:%d)\n", thread_id);
		dazukoUnregister_TS(&dazuko_id);
		return NULL;
	}

	printf("set access mask successfully (thread:%d)\n", thread_id);

	/* set scan path */
	for (i=1 ; i<argc ; i++)
	{
		if (argv[i][0] == '/')
		{
			if (dazukoAddIncludePath_TS(dazuko_id, argv[i]) != 0)
			{
				printf("error: failed to add %s include path (thread:%d)\n", argv[i], thread_id);
				dazukoUnregister_TS(&dazuko_id);
				return NULL;
			}

			args_ok = 1;
		}
	}

	/* ignore /dev/ */
	if (dazukoAddExcludePath_TS(dazuko_id, "/dev/") != 0)
	{
		printf("error: failed to add /dev/ exclude path (thread:%d)\n", thread_id);
		dazukoUnregister_TS(&dazuko_id);
		return NULL;
	}

	if (!args_ok)
	{
		print_usage();
		dazukoUnregister_TS(&dazuko_id);
		return NULL;
	}

	printf("set scan path successfully (thread:%d)\n", thread_id);

	while (RUNNING)
	{
		/* get an access */
		if (dazukoGetAccess_TS(dazuko_id, &acc) == 0)
		{
			print_access(acc, thread_id);

			/* always allow access */
			acc->deny = 0;

			/* return access (IMPORTANT, the kernel is waiting for us!) */
			if (dazukoReturnAccess_TS(dazuko_id, &acc) != 0)
			{
				printf("error: failed to return access (thread:%d)\n", thread_id);
				RUNNING = 0;
			}
		}
		else if (RUNNING)
		{
			printf("warning: failed to get an access (thread:%d)\n", thread_id);
			RUNNING = 0;
		}
	}

	/* unregister with Dazuko */
	if (dazukoUnregister_TS(&dazuko_id) != 0)
	{
		printf("error: failed to unregister with Dazuko (thread:%d)\n", thread_id);
		return NULL;
	}

	printf("unregistered with Dazuko successfully (thread:%d)\n", thread_id);

	return NULL;
}

int main(int argc, char *argv[])
{
	pthread_t	tid[NUMBER_OF_THREADS];
	int		i;
	sigset_t	sigset;

	/* detect TERM signals */
	signal(SIGTERM, sigterm);

	/* detect INT signals */
	signal(SIGINT, sigterm);

	/* detect USR1 signals */
	signal(SIGUSR1, sigterm);

	/* ignore SIGUSR1 (only used by threads) */
	if (sigemptyset(&sigset) == 0)
	{
		sigaddset(&sigset, SIGUSR1);
		sigprocmask(SIG_BLOCK, &sigset, NULL);
	}

	for (i=0 ; i<NUMBER_OF_THREADS ; i++)
	{
		/* set the id for the thread */
		id[i].thread_id = i;

		/* set argc,argv for the thread */
		id[i].argc = argc;
		id[i].argv = argv;

		/* create the thread */
		pthread_create(&(tid[i]), NULL, main_loop, &(id[i]));
	}

	/* wait until shutdown */
	while (RUNNING)
	{
		sleep(1);
	}

	for (i=0 ; i<NUMBER_OF_THREADS ; i++)
	{
		/* notify threads to terminate */
		pthread_kill(tid[i], SIGUSR1);
	}

	for (i=0 ; i<NUMBER_OF_THREADS ; i++)
	{
		/* wait for the thread to finish */
		pthread_join(tid[i], NULL);
	}

	return 0;
}
