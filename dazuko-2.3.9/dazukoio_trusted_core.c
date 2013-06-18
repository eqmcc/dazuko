/* Dazuko Interface. Interace with Dazuko for file access control.
   Written by John Ogness <dazukocode@ogness.net>

   Copyright (c) 2005 H+BEDV Datentechnik GmbH
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
#include "dazukoio.h"
#include "dazukoio_core.h"
#include "dazuko_transport.h"
#include "dazukoio_trusted.h"

int dazukoRegisterTrusted(const char *groupName, const char *token, int flags)
{
	struct dazuko_request	*request;
	char			buffer[ITOA_SIZE];
	dazuko_id_t		*temp_id;
	size_t			size;

	if (groupName == NULL || token == NULL)
		return -1;

	/* create temporary id */
	temp_id = (dazuko_id_t *)malloc(sizeof(dazuko_id_t));
	if (temp_id == NULL)
		return -1;

	memset(temp_id, 0, sizeof(dazuko_id_t));

	temp_id->comm_mode = DAZUKO_COMM_REQSTREAM;

	/* open device */
	if (xp_connection_open(temp_id) != 0)
	{
		free(temp_id);
		return -1;
	}

	request = (struct dazuko_request *)malloc(sizeof(struct dazuko_request));
	if (request == NULL)
	{
		xp_connection_close(temp_id);
		free(temp_id);
		return -1;
	}

	memset(request, 0, sizeof(struct dazuko_request));

	request->type[0] = REGISTER_TRUSTED;

	size = 1 + 2 + 1 + strlen(groupName); /* \nGN=groupName */
	size += 1 + 2 + 1 + strlen(token); /* \nTT=token */
	if (flags & DAZUKO_TRUST_CHILDREN)
	{
		size += 1 + 2 + 1 + 1; /* \nTF=C */
	}
	size += 1; /* \0 */

	request->buffer = (char *)malloc(size);
	if (request->buffer == NULL)
	{
		xp_connection_close(temp_id);
		free(temp_id);
		free(request);
		return -1;
	}
	snprintf(request->buffer, size, "\nGN=%s\nTT=%s%s", groupName, token, (flags & DAZUKO_TRUST_CHILDREN) ? "\nTF=C" : "");
	request->buffer[size - 1] = 0;

	request->buffer_size = strlen(request->buffer) + 1;

	size = 4096;
	request->reply_buffer = (char *)malloc(size);
	if (request->reply_buffer == NULL)
	{
		xp_connection_close(temp_id);
		free(temp_id);
		free(request->buffer);
		free(request);
		return -1;
	}
	memset(request->reply_buffer, 0, size);
	request->reply_buffer_size = size;

	if (process_request(temp_id, buffer, sizeof(buffer), request, 1) != 0)
	{
		xp_connection_close(temp_id);
		free(temp_id);
		free(request->buffer);
		free(request->reply_buffer);
		free(request);

		return -1;
	}

	if (dazuko_get_value("\nDN=", request->reply_buffer, buffer, sizeof(buffer)) != 0)
	{
		xp_connection_close(temp_id);
		free(temp_id);
		free(request->buffer);
		free(request->reply_buffer);
		free(request);

		return -1;
	}

	xp_connection_close(temp_id);
	free(temp_id);
	free(request->buffer);
	free(request->reply_buffer);
	free(request);

	if (atoi(buffer) != 0)
		return -1;

	return 0;
}

int dazukoUnregisterTrusted(void)
{
	struct dazuko_request	*request;
	char			buffer[ITOA_SIZE];
	dazuko_id_t		*temp_id;
	int			error = 0;

	/* create temporary id */
	temp_id = (dazuko_id_t *)malloc(sizeof(dazuko_id_t));
	if (temp_id == NULL)
		return -1;

	memset(temp_id, 0, sizeof(dazuko_id_t));

	/* open device */
	if (xp_connection_open(temp_id) != 0)
	{
		free(temp_id);
		return -1;
	}

	request = (struct dazuko_request *)malloc(sizeof(struct dazuko_request));
	if (request == NULL)
	{
		free(temp_id);
		return -1;
	}

	memset(request, 0, sizeof(struct dazuko_request));

	request->type[0] = UNREGISTER_TRUSTED;

	if (process_request(temp_id, buffer, sizeof(buffer), request, 0) != 0)
	{
		error = -1;
	}

	xp_connection_close(temp_id);
	free(temp_id);
	free(request);

	return error;
}

