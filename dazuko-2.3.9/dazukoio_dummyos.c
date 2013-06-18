/* Dazuko Dummy Interface. Dazuko interface implementatoin for Dummies.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "dazukoio_dummyos.h"
#include "dazukoio_core.h"


/* connection to Dazuko */

int xp_connection_open(struct dazuko_id *id)
{
	struct sockaddr_in	sa;

	if (id == NULL)
		return -1;

	if (id->extra_data != NULL)
		return -1;

	id->extra_data = (struct xp_dazukoio_id *)malloc(sizeof(struct xp_dazukoio_id));
	if (id->extra_data == NULL)
		return -1;

	id->extra_data->fd = socket(AF_INET, SOCK_STREAM, 0);
	if (id->extra_data->fd < 0)
	{
		free(id->extra_data);
		id->extra_data = NULL;
		return -1;
	}

	memset(&sa, 0, sizeof(struct sockaddr_in));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(61234);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (connect(id->extra_data->fd, (struct sockaddr *)&sa, sizeof(sa)) != 0)
		return -1;

	if (id->extra_data->fd < 0)
	{
		free(id->extra_data);
		id->extra_data = NULL;
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

	if (id->extra_data->fd >= 0)
		close(id->extra_data->fd);

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

	if (id->extra_data->fd < 0)
		return -1;

	return 0;
}


/* process requests */

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

int xp_process_request(struct dazuko_id *id, const char *buffer, size_t buffer_size)
{
	struct dazuko_request	*request;
	char			value[ITOA_SIZE];
	char			*tmp_buffer;
	char			*tmp_reply_buffer;

	if (buffer == NULL || buffer_size <= 0)
		return -1;

	if (xp_verify_id(id) != 0)
		return -1;

	if (dazuko_get_value("\nRA=", buffer, value, sizeof(value)) != 0)
		return -1;

	request = (struct dazuko_request *)atol(value);

	if (fullwrite(id->extra_data->fd, request, sizeof(struct dazuko_request)) != 0)
		return -1;

	if (request->buffer_size > 0)
	{
		if (fullwrite(id->extra_data->fd, request->buffer, request->buffer_size) != 0)
			return -1;
	}

	if (request->reply_buffer_size > 0)
	{
		if (fullwrite(id->extra_data->fd, request->reply_buffer, request->reply_buffer_size) != 0)
			return -1;
	}

	/* we now have sent the full request */

	tmp_buffer = request->buffer;
	tmp_reply_buffer = request->reply_buffer;

	if (fullread(id->extra_data->fd, request, sizeof(struct dazuko_request)) != 0)
		return -1;

	request->buffer = tmp_buffer;
	request->reply_buffer = tmp_reply_buffer;

	if (request->buffer_size > 0)
	{
		if (fullread(id->extra_data->fd, request->buffer, request->buffer_size) != 0)
			return -1;
	}

	if (request->reply_buffer_size > 0)
	{
		if (fullread(id->extra_data->fd, request->reply_buffer, request->reply_buffer_size) != 0)
			return -1;
	}

	/* we now received the request response */

	return 0;
}
