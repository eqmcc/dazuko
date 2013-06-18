/* Dazuko Interface. Interace with Dazuko 1.x for file access control.
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "dazukoio_linux_compat1.h"

int dazukoRegister_TS_compat1_wrapper(struct dazuko_id **dazuko_id, const char *groupName)
{
	int			ret;
	struct dazuko_id	*temp_id;

	if (dazuko_id == NULL)
		return -1;

	temp_id = (struct dazuko_id *)malloc(sizeof(struct dazuko_id));
	if (temp_id == NULL)
		return -1;

	memset(temp_id, 0, sizeof(struct dazuko_id));

	temp_id->extra_data = (struct xp_dazukoio_id *)malloc(sizeof(struct xp_dazukoio_id));
	if (temp_id->extra_data == NULL)
	{
		free(temp_id);
		return -1;
	}

	temp_id->extra_data->device = -1;
	temp_id->extra_data->dev_major = -1;

	ret = dazukoRegister_TS_compat1(temp_id, groupName);

	if (ret == 0)
	{
		*dazuko_id = temp_id;
	}
	else
	{
		free(temp_id->extra_data);
		free(temp_id);
	}

	return ret;
}

int dazukoRegister_TS_compat1(struct dazuko_id *dazuko, const char *groupName)
{
	struct option_compat1	*opt;
	char			buffer[10];

	if (dazuko == NULL)
		return -1;

	if (dazuko->extra_data == NULL)
		return -1;

	if (groupName == NULL)
		groupName = "_GENERIC";

	if (dazuko->extra_data->device < 0)
	{

		dazuko->extra_data->device = open("/dev/dazuko", 0);
		if (dazuko->extra_data->device < 0)
			return -1;

		memset(buffer, 0, sizeof(buffer));
		if (read(dazuko->extra_data->device, buffer, sizeof(buffer)-1) < 1)
		{
			close(dazuko->extra_data->device);
			dazuko->extra_data->device = -1;
			return -1;
		}

		dazuko->extra_data->dev_major = atoi(buffer);
	}

	opt = (struct option_compat1 *)malloc(sizeof(struct option_compat1));
	if (opt == NULL)
	{
		close(dazuko->extra_data->device);
		dazuko->extra_data->device = -1;
		dazuko->extra_data->dev_major = -1;
		return -1;
	}

	memset(opt, 0, sizeof(struct option_compat1));

	opt->command = REGISTER;
	strncpy(opt->buffer, groupName, sizeof(opt->buffer) - 1);
	opt->buffer_length = strlen(opt->buffer) + 1;

	if (ioctl(dazuko->extra_data->device, _IOW(dazuko->extra_data->dev_major, IOCTL_SET_OPTION, void *), opt) != 0)
	{
		/* if this fails, it could be a really old version */

		/* the original versions registered automatically with open() */
	}

	free(opt);

	return 0;
}

int dazukoSetAccessMask_TS_compat1(struct dazuko_id *dazuko, unsigned long accessMask)
{
	struct option_compat1	*opt;
	int			err = 0;

	if (dazuko == NULL)
		return -1;

	if (dazuko->extra_data == NULL)
		return -1;

	if (dazuko->extra_data->device < 0 || dazuko->extra_data->dev_major < 0)
		return -1;

	opt = (struct option_compat1 *)malloc(sizeof(struct option_compat1));
	if (opt == NULL)
		return -1;

	memset(opt, 0, sizeof(struct option_compat1));

	opt->command = SET_ACCESS_MASK;
	opt->buffer[0] = (char)accessMask;
	opt->buffer_length = 1;

	if (ioctl(dazuko->extra_data->device, _IOW(dazuko->extra_data->dev_major, IOCTL_SET_OPTION, void *), opt) != 0)
		err = -1;

	free(opt);

	return err;
}

int dazuko_set_path_compat1(struct dazuko_id *dazuko, const char *path, int command)
{
	struct option_compat1	*opt;
	int			err = 0;

	if (dazuko == NULL)
		return -1;

	if (dazuko->extra_data == NULL)
		return -1;

	if (path == NULL)
		return -1;

	if (dazuko->extra_data->device < 0 || dazuko->extra_data->dev_major < 0)
		return -1;

	opt = (struct option_compat1 *)malloc(sizeof(struct option_compat1));
	if (opt == NULL)
		return -1;

	memset(opt, 0, sizeof(struct option_compat1));

	opt->command = command;
	strncpy(opt->buffer, path, sizeof(opt->buffer) - 1);
	opt->buffer_length = strlen(opt->buffer) + 1;

	if (ioctl(dazuko->extra_data->device, _IOW(dazuko->extra_data->dev_major, IOCTL_SET_OPTION, void *), opt) != 0)
		err = -1;

	free(opt);

	return err;
}

int dazukoAddIncludePath_TS_compat1(struct dazuko_id *dazuko, const char *path)
{
	return dazuko_set_path_compat1(dazuko, path, ADD_INCLUDE_PATH);
}

int dazukoAddExcludePath_TS_compat1(struct dazuko_id *dazuko, const char *path)
{
	return dazuko_set_path_compat1(dazuko, path, ADD_EXCLUDE_PATH);
}

int dazukoRemoveAllPaths_TS_compat1(struct dazuko_id *dazuko)
{
	struct option_compat1	*opt;
	int			err = 0;

	if (dazuko == NULL)
		return -1;

	if (dazuko->extra_data == NULL)
		return -1;

	if (dazuko->extra_data->device < 0 || dazuko->extra_data->dev_major < 0)
		return -1;

	opt = (struct option_compat1 *)malloc(sizeof(struct option_compat1));
	if (opt == NULL)
		return -1;

	memset(opt, 0, sizeof(struct option_compat1));

	opt->command = REMOVE_ALL_PATHS;
	opt->buffer_length = 0;

	if (ioctl(dazuko->extra_data->device, _IOW(dazuko->extra_data->dev_major, IOCTL_SET_OPTION, void *), opt) != 0)
		err = -1;

	free(opt);

	return err;
}

int dazukoGetAccess_TS_compat1_wrapper(struct dazuko_id *dazuko, struct dazuko_access **acc)
{
	struct access_compat1	acc_compat1;
	struct dazuko_access	*temp_acc;
	int			ret;

	if (acc == NULL)
		return -1;

	*acc = NULL;

	temp_acc = (struct dazuko_access *)malloc(sizeof(struct dazuko_access));
	if (temp_acc == NULL)
		return -1;

	memset(temp_acc, 0, sizeof(struct dazuko_access));

	ret = dazukoGetAccess_TS_compat1(dazuko, &acc_compat1);

	if (ret == 0)
	{
		temp_acc->deny = acc_compat1.deny;
		temp_acc->event = acc_compat1.event;
		temp_acc->set_event = 1;
		temp_acc->flags = acc_compat1.o_flags;
		temp_acc->set_flags = 1;
		temp_acc->mode = acc_compat1.o_mode;
		temp_acc->set_mode = 1;
		temp_acc->uid = acc_compat1.uid;
		temp_acc->set_uid = 1;
		temp_acc->pid = acc_compat1.pid;
		temp_acc->set_pid = 1;
		temp_acc->filename = strdup(acc_compat1.filename);
		temp_acc->set_filename = 1;

		*acc = temp_acc;
	}
	else
	{
		free(temp_acc);
	}

	return ret;
}

int dazukoGetAccess_TS_compat1(struct dazuko_id *dazuko, struct access_compat1 *acc)
{
	if (dazuko == NULL)
		return -1;

	if (dazuko->extra_data == NULL)
		return -1;

	if (acc == NULL)
		return -1;

	if (dazuko->extra_data->device < 0 || dazuko->extra_data->dev_major < 0)
		return -1;

	memset(acc, 0, sizeof(struct access_compat1));

	if (ioctl(dazuko->extra_data->device, _IOR(dazuko->extra_data->dev_major, IOCTL_GET_AN_ACCESS, struct access_compat1 *), acc) != 0)
		return -1;

	return 0;
}

int dazukoReturnAccess_TS_compat1_wrapper(struct dazuko_id *dazuko, struct dazuko_access **acc, int return_access, int free_access)
{
	struct access_compat1	acc_compat1;
	int			ret = 0;

	if (acc == NULL)
		return -1;

	if (*acc == NULL)
		return -1;

	if (return_access)
	{
		memset(&acc_compat1, 0, sizeof(acc_compat1));

		acc_compat1.deny = (*acc)->deny;
		acc_compat1.event = (*acc)->event;
		acc_compat1.o_flags = (*acc)->flags;
		acc_compat1.o_mode = (*acc)->mode;
		acc_compat1.uid = (*acc)->uid;
		acc_compat1.pid = (*acc)->pid;
		if ((*acc)->filename != NULL)
		{
			strncpy(acc_compat1.filename, (*acc)->filename, sizeof(acc_compat1.filename) - 1);
			acc_compat1.filename[sizeof(acc_compat1.filename) - 1] = 0;
		}

		ret = dazukoReturnAccess_TS_compat1(dazuko, &acc_compat1);
	}

	if (free_access && ret == 0)
	{
		if ((*acc)->filename != NULL)
			free((*acc)->filename);
		free(*acc);
		*acc = NULL;
	}

	return ret;
}

int dazukoReturnAccess_TS_compat1(struct dazuko_id *dazuko, struct access_compat1 *acc)
{
	if (dazuko == NULL)
		return -1;

	if (dazuko->extra_data == NULL)
		return -1;

	if (acc == NULL)
		return -1;

	if (dazuko->extra_data->device < 0 || dazuko->extra_data->dev_major < 0)
		return -1;

	if (ioctl(dazuko->extra_data->device, _IOW(dazuko->extra_data->dev_major, IOCTL_RETURN_ACCESS, struct access_compat1 *), acc) != 0)
		return -1;

	return 0;
}

int dazukoUnregister_TS_compat1_wrapper(struct dazuko_id **dazuko_id)
{
	int	ret;

	if (dazuko_id == NULL)
		return -1;

	ret = dazukoUnregister_TS_compat1(*dazuko_id);

	if (ret == 0)
	{
		free(*dazuko_id);
		*dazuko_id = NULL;
	}

	return ret;
}

int dazukoUnregister_TS_compat1(struct dazuko_id *dazuko)
{
	int		error = -1;

	if (dazuko == NULL)
		return -1;

	if (dazuko->extra_data == NULL)
		return -1;

	if (dazuko->extra_data->device >= 0)
		error = close(dazuko->extra_data->device);

	free(dazuko->extra_data);
	dazuko->extra_data = NULL;

	return error;
}
