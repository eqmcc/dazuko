/* Example program demonstrating the capabilities/interface of Dazuko.
   Written by John Ogness <dazukocode@ogness.net>

   Copyright (c) 2002, 2003, 2004, 2005 H+BEDV Datentechnik GmbH
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
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include "dazukoio.h"

int	RUNNING = 1;	/* flag for main loop */

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

void print_access(struct dazuko_access *acc)
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

	printf("\n");

	fflush(stdout);
}

int main(int argc, char *argv[])
{
	struct dazuko_access	*acc;
	int			args_ok = 0;
	int			i;
	struct dazuko_version	ver;

	if (dazukoIOVersion(&ver) != 0)
	{
		printf("error: failed to read DazukoIO version\n");
		return -1;
	}

	printf("DazukoIO version %s (%d.%d.%d.%d)\n", ver.text, ver.major, ver.minor, ver.revision, ver.release);

	/* register with dazuko */
	if (dazukoRegister("DAZUKO_EXAMPLE", "r+") != 0)
	{
		printf("error: failed to register with Dazuko\n");
		return -1;
	}

	printf("registered with Dazuko successfully\n");

	if (dazukoVersion(&ver) != 0)
	{
		printf("error: failed to read Dazuko version\n");
		dazukoUnregister();
		return -1;
	}

	printf("Dazuko version %s (%d.%d.%d.%d)\n", ver.text, ver.major, ver.minor, ver.revision, ver.release);

	/* detect TERM signals */
	signal(SIGTERM, sigterm);

	/* detect INT signals */
	signal(SIGINT, sigterm);

	/* set access mask */
	if (dazukoSetAccessMask(DAZUKO_ON_OPEN | DAZUKO_ON_CLOSE | DAZUKO_ON_CLOSE_MODIFIED | DAZUKO_ON_EXEC | DAZUKO_ON_UNLINK | DAZUKO_ON_RMDIR) != 0)
	{
		printf("error: failed to set access mask\n");
		dazukoUnregister();
		return -1;
	}

	printf("set access mask successfully\n");

	/* set scan path */
	for (i=1 ; i<argc ; i++)
	{
		if (argv[i][0] == '/')
		{
			if (dazukoAddIncludePath(argv[i]) != 0)
			{
				printf("error: failed to add %s include path\n", argv[i]);
				dazukoUnregister();
				return -1;
			}

			args_ok = 1;
		}
	}

	/* ignore /dev/ */
	if (dazukoAddExcludePath("/dev/") != 0)
	{
		printf("error: failed to add /dev/ exclude path\n");
		dazukoUnregister();
		return -1;
	}

	if (!args_ok)
	{
		print_usage();
		dazukoUnregister();
		return -1;
	}

	printf("set scan path successfully\n");

	while (RUNNING)
	{
		/* get an access */
		if (dazukoGetAccess(&acc) == 0)
		{
			print_access(acc);

			/* always allow access */
			acc->deny = 0;

			/* return access (IMPORTANT, the kernel is waiting for us!) */
			if (dazukoReturnAccess(&acc) != 0)
			{
				printf("error: failed to return access\n");
				RUNNING = 0;
			}
		}
		else if (RUNNING)
		{
			printf("warning: failed to get an access\n");
			RUNNING = 0;
		}
	}

	/* unregister with Dazuko */
	if (dazukoUnregister() != 0)
	{
		printf("error: failed to unregister with Dazuko\n");
		return -1;
	}

	printf("unregistered with Dazuko successfully\n");

	return 0;
}
