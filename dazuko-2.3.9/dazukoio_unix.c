/* Dazuko UNIX Interface. Dazuko interface implementatoin for UNIX.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include "dazukoio_unix.h"
#include "dazukoio_core.h"


/* connection to Dazuko */

int xp_connection_open(struct dazuko_id *id)
{
	char	buffer[ITOA_SIZE];

	if (id == NULL)
		return -1;

	if (id->extra_data != NULL)
		return -1;

	id->extra_data = (struct xp_dazukoio_id *)malloc(sizeof(struct xp_dazukoio_id));
	if (id->extra_data == NULL)
		return -1;

	id->extra_data->device = -1;
	id->extra_data->dev_major = -1;

	/* open device */
	id->extra_data->device = open("/dev/dazuko", O_RDWR);
	if (id->extra_data->device < 0)
	{
		free(id->extra_data);
		id->extra_data = NULL;
		return -1;
	}

	/* read device major number */
	memset(buffer, 0, sizeof(buffer));
	if (read(id->extra_data->device, buffer, sizeof(buffer)-1) < 1)
	{
		xp_connection_close(id);
		return -1;
	}

	id->extra_data->dev_major = atoi(buffer);
	if (id->extra_data->dev_major < 0)
	{
		xp_connection_close(id);
		return -1;
	}

	return 0;
}

int xp_connection_close(struct dazuko_id *id)
{
	if (id == NULL)
		return -1;

	if (id->extra_data == NULL)
		return -1;

	close(id->extra_data->device);
	free(id->extra_data);
	id->extra_data = NULL;

	return 0;
}


/* verify id validity */

int xp_verify_id(struct dazuko_id *id)
{
	if (id == NULL)
		return -1;

	if (id->extra_data == NULL)
		return -1;

	if (id->extra_data->device < 0 || id->extra_data->dev_major < 0)
		return -1;

	return 0;
}


/* process requests */

int xp_process_request(struct dazuko_id *id, const char *buffer, size_t buffer_size)
{
	if (buffer == NULL || buffer_size <= 0)
		return -1;

	if (xp_verify_id(id) != 0)
		return -1;

	if (write(id->extra_data->device, buffer, buffer_size) != buffer_size)
		return -1;

	return 0;
}
