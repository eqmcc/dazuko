/* Dazuko Interface. Interace with Dazuko for file access control.
   Written by John Ogness <dazukocode@ogness.net>

   Copyright (c) 2002, 2003, 2004, 2005, 2006 H+BEDV Datentechnik GmbH
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
#include "dazuko_version.h"

#if !defined(NO_COMPAT1)
#include "dazukoio_linux_compat1.h"
#endif

/* binary version stamp */
const char	*DAZUKO_VERSION_STAMP = "\nDazukoVersion=" DAZUKO_VERSION_MAJOR "." DAZUKO_VERSION_MINOR "." DAZUKO_VERSION_REVISION "." DAZUKO_VERSION_RELEASE "\n";

/* version string for display */
const char	*VERSION_STRING = DAZUKO_VERSION_MAJOR "." DAZUKO_VERSION_MINOR "." DAZUKO_VERSION_REVISION
#ifdef DAZUKO_PRERELEASE
"-pre" DAZUKO_VERSION_RELEASE
#endif
;

/* this is just a large number to "guarentee"
   to contain the full filename */
#define DAZUKO_FILENAME_MAX_LENGTH	6144

dazuko_id_t	*_GLOBAL_DAZUKO = NULL;

static int			_GLOBAL_SET_DAZUKO_VERSION = 0;
static struct dazuko_version	_GLOBAL_DAZUKO_VERSION;


static inline char char_to_hex(char c)
{
	/* ugly, but fast */

	switch (c)
	{
		case '1': return 1;
		case '2': return 2;
		case '3': return 3;
		case '4': return 4;
		case '5': return 5;
		case '6': return 6;
		case '7': return 7;
		case '8': return 8;
		case '9': return 9;
		case 'a': case 'A': return 10;
		case 'b': case 'B': return 11;
		case 'c': case 'C': return 12;
		case 'd': case 'D': return 13;
		case 'e': case 'E': return 14;
		case 'f': case 'F': return 15;
	}

	return 0;
}

static void unescape_string(char *string)
{
	char	*p;

	for (p=string ; *p ; p++)
	{
		/* check if we have \x */
		if ((*p == '\\') && (*(p+1) == 'x'))
		{
			/* this is not cheap, but it should not occur often */

			/* check if we have two more values following \x */
			if (*(p+2) && *(p+3))
			{
				*p = char_to_hex(*(p+2));
				*p <<= 4;
				*p |= char_to_hex(*(p+3));

				memmove(p + 1, p + 4, strlen(p+4) + 1);
			}
		}
	}
}

int dazuko_get_value(const char *key, const char *string, char *buffer, size_t buffer_size)
{
	const char	*p1;
	const char	*p2;
	size_t		size;

	if (buffer == NULL || buffer_size < 1)
		return -1;

	buffer[0] = 0;

	if (key == NULL || string == NULL)
		return -1;

	p1 = strstr(string, key);
	if (p1 == NULL)
		return -1;

	p1 += strlen(key);

	for (p2=p1 ; *p2 && *p2!='\n' ; p2++)
		continue;

	size = p2 - p1;
	if (size >= buffer_size)
		size = buffer_size - 1;

	memcpy(buffer, p1, size);

	buffer[size] = 0;

	return 0;
}

static struct dazuko_request *alloc_request(int type, int request_length, int response_length)
{
	struct dazuko_request	*request;
	char			*s;

	request = (struct dazuko_request *)malloc(sizeof(struct dazuko_request));
	if (request == NULL)
		return NULL;

	memset(request, 0, sizeof(struct dazuko_request));

	request->type[0] = (char)type;

	s = (char *)malloc(request_length);
	if (s == NULL)
	{
		free(request);
		return NULL;
	}

	memset(s, 0, request_length);

	request->buffer = s;

	/* Note: buffer and buffer_size should be set after
	 * calling this function */

	if (response_length > 0)
	{
		s = (char *)malloc(response_length);
		if (s == NULL)
		{
			free(request->buffer);
			free(request);
			return NULL;
		}

		memset(s, 0, response_length);

		request->reply_buffer = s;
		request->reply_buffer_size = response_length;
	}

	return request;
}

static void free_request(struct dazuko_request **request_ref)
{
	struct dazuko_request	*request;

	if (request_ref == NULL)
		return;

	request = *request_ref;

	if (request == NULL)
		return;

	if (request->buffer != NULL)
		free(request->buffer);

	if (request->reply_buffer != NULL)
		free(request->reply_buffer);

	free(request);

	*request_ref = NULL;
}

int dazukoVersion(struct dazuko_version *version)
{
	if (version == NULL)
		return -1;

	if (!_GLOBAL_SET_DAZUKO_VERSION)
		return -1;

	memcpy(version, &_GLOBAL_DAZUKO_VERSION, sizeof(struct dazuko_version));

	return 0;
}

int dazukoIOVersion(struct dazuko_version *version)
{
	if (version == NULL)
		return -1;

	memset(version, 0, sizeof(struct dazuko_version));

	version->major = atoi(DAZUKO_VERSION_MAJOR);
	version->minor = atoi(DAZUKO_VERSION_MINOR);
	version->revision = atoi(DAZUKO_VERSION_REVISION);
	version->release = atoi(DAZUKO_VERSION_RELEASE);

	snprintf(version->text, sizeof(version->text), "%s", VERSION_STRING);
	version->text[sizeof(version->text) - 1] = 0;

	return 0;
}

int dazukoRegister(const char *groupName, const char *mode)
{
	return dazukoRegister_TS(&_GLOBAL_DAZUKO, groupName, mode);
}

int process_request(struct dazuko_id *id, char *buffer, size_t buffer_size, struct dazuko_request *request, int reply_required)
{
	unsigned char	*llreq = NULL;
	int		error = 0;
	size_t		size;

	switch (id->comm_mode)
	{
		case DAZUKO_COMM_REQSTREAM:
			/* we add an extra 4 bytes as "size of chunk 1" */
			size = dazuko_reqstream_dim_chunk0(sizeof(char), sizeof(int), sizeof(void *)) + 4;

			llreq = (unsigned char *)malloc(size);
			if (llreq == NULL)
				return -1;

			/* this is especially important for the last 4 bytes */
			memset(llreq, 0, size);

			if (dazuko_reqstream_hl2ll(request, llreq) != 0)
			{
				free(llreq);
				return -1;
			}
			snprintf(buffer, buffer_size, "\nra=%lu", (unsigned long)llreq);
			break;

		case DAZUKO_COMM_DEVWRITE:
			snprintf(buffer, buffer_size, "\nRA=%lu", (unsigned long)request);
			break;

		default:
			/* Why are we here? _This_ function does
			 * not support other comm modes. */

			return -1;
	}

	buffer[buffer_size - 1] = 0;

	error = xp_process_request(id, buffer, strlen(buffer) + 1);

	if (reply_required && !error && id->comm_mode == DAZUKO_COMM_REQSTREAM)
	{
		if (dazuko_reqstream_ll2hl(llreq, request, 1) != 0)
		{
			/* this could be dangerous if it happens */
			error = -1;
		}
	}

	if (llreq != NULL)
		free(llreq);

	return error;
}

#define DAZUKO_SET_VERSION(maj, min, rev, rel, txt) \
{ \
	if (!_GLOBAL_SET_DAZUKO_VERSION) \
	{ \
		_GLOBAL_DAZUKO_VERSION.major = maj; \
		_GLOBAL_DAZUKO_VERSION.minor = min; \
		_GLOBAL_DAZUKO_VERSION.revision = rev; \
		_GLOBAL_DAZUKO_VERSION.release = rel; \
		snprintf(_GLOBAL_DAZUKO_VERSION.text, sizeof(_GLOBAL_DAZUKO_VERSION.text), txt); \
		_GLOBAL_DAZUKO_VERSION.text[sizeof(_GLOBAL_DAZUKO_VERSION.text) - 1] = 0; \
		_GLOBAL_SET_DAZUKO_VERSION = 1; \
	} \
}

static void dazuko_set_version(const char *reply_buffer)
{
	char	vn_buffer[ITOA_SIZE + DAZUKO_VERSION_TEXT_SIZE];
	char	vs_buffer[ITOA_SIZE + DAZUKO_VERSION_TEXT_SIZE];
	int	maj = 0;
	int	min = 0;
	int	rev = 0;
	int	rel = 0;
	char	*p1;
	char	*p2;
	int	error = 0;

#define DAZUKO_POP_NUMBER(num) \
{ \
	if (p1 == NULL) \
	{ \
		error = 1; \
	} \
	else \
	{ \
		p2 = strchr(p1, '.'); \
		if (p2 != NULL) \
		{ \
			*p2 = 0; \
			p2++; \
		} \
		num = atoi(p1); \
		p1 = p2; \
	} \
}

	if (dazuko_get_value("\nVN=", reply_buffer, vn_buffer, sizeof(vn_buffer)) != 0)
	{
		error = 1;
	}

	if (!error && dazuko_get_value("\nVS=", reply_buffer, vs_buffer, sizeof(vs_buffer)) != 0)
	{
		error = 1;
	}

	if (!error)
	{
		p1 = vn_buffer;
		DAZUKO_POP_NUMBER(maj);
		DAZUKO_POP_NUMBER(min);
		DAZUKO_POP_NUMBER(rev);
		DAZUKO_POP_NUMBER(rel);
	}

	if (error)
	{
		/* this should never occur unless someone used a CVS snapshot */
		DAZUKO_SET_VERSION(2, 1, 0, 0, "2.1.0-prex");
	}
	else
	{
		DAZUKO_SET_VERSION(maj, min, rev, rel, vs_buffer);
	}
}

/*
 * "inner" part of the REGISTER function: try to register with the kernel while
 * using one communication method; the caller might invoke us multiple times
 * after adjusting a few compatibility flags
 */
static int dazukoRegister_TS_inner(dazuko_id_t **dazuko_id, const char *groupName, const char *mode, int comm_mode)
{
	struct dazuko_request	*request;
	char			buffer[ITOA_SIZE];
	char			regMode[3];
	dazuko_id_t		*temp_id;
	size_t			size;
	int			write_mode = 0;
#if !defined(NO_COMPAT1)
	int			compat1_ret;
#endif

	if (dazuko_id == NULL)
		return -1;

	/* set default group name if one was not given */
	if (groupName == NULL)
		groupName = "_GENERIC";

	/* set default mode if one was not given */
	if (mode == NULL)
		mode = "r";

	if (strcasecmp(mode, "r") == 0)
	{
		strncpy(regMode, "R", sizeof(regMode));
		write_mode = 0;
	}
	else if (strcasecmp(mode, "r+") == 0 || strcasecmp(mode, "rw") == 0)
	{
		strncpy(regMode, "RW", sizeof(regMode));
		write_mode = 1;
	}
	else
	{
		return -1;
	}
	regMode[sizeof(regMode) - 1] = 0;

#if !defined(NO_COMPAT1)
	/* shortcut for the compat12 layer */
	if (comm_mode == DAZUKO_COMM_COMPAT1)
	{
		compat1_ret = dazukoRegister_TS_compat1_wrapper(dazuko_id, groupName);

		if (compat1_ret == 0)
		{
			(*dazuko_id)->write_mode = write_mode;

			DAZUKO_SET_VERSION(1, 0, 0, 0, "1.x");
		}

		return compat1_ret;
	}
	/* fallthrough to the device writing path */
#endif

	/* create temporary id */
	temp_id = (dazuko_id_t *)malloc(sizeof(dazuko_id_t));
	if (temp_id == NULL)
		return -1;

	memset(temp_id, 0, sizeof(dazuko_id_t));

	temp_id->comm_mode = comm_mode;

	/* open device */
	if (xp_connection_open(temp_id) != 0)
	{
		free(temp_id);
		return -1;
	}

	/* allocate a request, fill in "RM=" and "GN=" */
	size = 1 + 2 + 1 + strlen(regMode) /* \nRM=mode */
		+ 1 + 2 + 1 + strlen(groupName) /* \nGN=groupName */
		+ 1 /* \0 */
		;

	request = alloc_request(REGISTER, size, 4096);
	if (request == NULL)
	{
		xp_connection_close(temp_id);
		free(temp_id);
		return -1;
	}

	snprintf(request->buffer, size, "\nRM=%s\nGN=%s", regMode, groupName);
	request->buffer[size - 1] = 0;
	request->buffer_size = strlen(request->buffer) + 1;

	if (process_request(temp_id, buffer, sizeof(buffer), request, 1) != 0)
	{
		xp_connection_close(temp_id);
		free(temp_id);
		free_request(&request);

		return -1;
	}

	if (dazuko_get_value("\nID=", request->reply_buffer, buffer, sizeof(buffer)) != 0)
	{
		xp_connection_close(temp_id);
		free(temp_id);
		free_request(&request);

		return -1;
	}

	temp_id->id = atoi(buffer);

	if (temp_id->id < 0)
	{
		xp_connection_close(temp_id);
		free(temp_id);
		free_request(&request);

		return -1;
	}

	temp_id->write_mode = write_mode;

	if (temp_id->comm_mode == DAZUKO_COMM_REQSTREAM)
	{
		dazuko_set_version(request->reply_buffer);
	}
	else if (temp_id->comm_mode == DAZUKO_COMM_DEVWRITE)
	{
		DAZUKO_SET_VERSION(2, 0, 0, 0, "2.0.x");
	}

	free_request(&request);

	*dazuko_id = temp_id;

	return 0;
}

/*
 * "outer" part of the REGISTER function:  try to register, use from the most
 * current / most portable communication method down to the oldest
 * compatibility mode to talk to the kernel module
 *
 * we don't care too much about cost -- this happens only once at startup and
 * is done in the interest of the best possible compatbility while reaching for
 * best service quality (robustness, feature sets, parameters accessible, etc)
 *
 * we only try to fallback once at the REGISTER stage, every following
 * operation is done using the communication method we determine here
 */
int dazukoRegister_TS(dazuko_id_t **dazuko_id, const char *groupName, const char *mode)
{
	int	rc;
	int	comm_mode = DAZUKO_COMM_REQSTREAM;

	/* try to register until success or methods are exhausted */
	while (1)
	{
		/* stop if we succeeded to register */
		rc = dazukoRegister_TS_inner(dazuko_id, groupName, mode, comm_mode);
		if (rc == 0)
			break;

		/* try to fallback if possible */

		if (comm_mode == DAZUKO_COMM_REQSTREAM)
		{
			/* the "ra=" method failed, fallback to "RA=" */

			comm_mode = DAZUKO_COMM_DEVWRITE;
			continue;
		}

#if !defined(NO_COMPAT1)
		if (comm_mode == DAZUKO_COMM_DEVWRITE)
		{
			/* the "RA=" method failed, fallback to compat1 */

			comm_mode = DAZUKO_COMM_COMPAT1;
			continue;
		}
#endif

		comm_mode = DAZUKO_COMM_UNSET;

		/* we ran out of alternatives, return with an error */
		break;
	}

	return rc;
}

int dazukoSetAccessMask(unsigned long accessMask)
{
	return dazukoSetAccessMask_TS(_GLOBAL_DAZUKO, accessMask);
}

int dazukoSetAccessMask_TS(dazuko_id_t *dazuko_id, unsigned long accessMask)
{
	struct dazuko_request	*request;
	size_t			size;
	char			buffer[ITOA_SIZE];

	if (dazuko_id == NULL)
		return -1;

#if !defined(NO_COMPAT1)
	if (dazuko_id->comm_mode == DAZUKO_COMM_COMPAT1)
		return dazukoSetAccessMask_TS_compat1(dazuko_id, accessMask);
#endif

	if (dazuko_id->id < 0)
		return -1;

	if (xp_verify_id(dazuko_id) != 0)
		return -1;

	size = 1 + 2 + 1 + ITOA_SIZE /* \nID=id */
		+ 1 + 2 + 1 + ITOA_SIZE /* \nAM=accessMask */
		+ 1 /* \0 */
		;

	request = alloc_request(SET_ACCESS_MASK, size, 0);
	if (request == NULL)
		return -1;

	snprintf(request->buffer, size, "\nID=%d\nAM=%lu", dazuko_id->id, accessMask);
	request->buffer[size - 1] = 0;
	request->buffer_size = strlen(request->buffer) + 1;

	if (process_request(dazuko_id, buffer, sizeof(buffer), request, 0) != 0)
	{
		free_request(&request);
		return -1;
	}

	free_request(&request);

	return 0;
}

static int dazuko_set_path(dazuko_id_t *dazuko_id, const char *path, int type)
{
	struct dazuko_request	*request;
	size_t			size;
	char			buffer[ITOA_SIZE];

	if (dazuko_id == NULL)
		return -1;

	if (dazuko_id->id < 0)
		return -1;

	if (xp_verify_id(dazuko_id) != 0)
		return -1;

	if (path == NULL)
		return -1;

	size = 1 + 2 + 1 + ITOA_SIZE /* \nID=id */
		+ 1 + 2 + 1 + strlen(path) /* \nPT=path */
		+ 1 /* \0 */
		;

	request = alloc_request(type, size, 0);
	if (request == NULL)
		return -1;

	snprintf(request->buffer, size, "\nID=%d\nPT=%s", dazuko_id->id, path);
	request->buffer[size - 1] = 0;
	request->buffer_size = strlen(request->buffer) + 1;

	if (process_request(dazuko_id, buffer, sizeof(buffer), request, 0) != 0)
	{
		free_request(&request);
		return -1;
	}

	free_request(&request);

	return 0;
}

int dazukoAddIncludePath(const char *path)
{
	return dazukoAddIncludePath_TS(_GLOBAL_DAZUKO, path);
}

int dazukoAddIncludePath_TS(dazuko_id_t *dazuko_id, const char *path)
{
#if !defined(NO_COMPAT1)
	if (dazuko_id->comm_mode == DAZUKO_COMM_COMPAT1)
		return dazukoAddIncludePath_TS_compat1(dazuko_id, path);
#endif

	return dazuko_set_path(dazuko_id, path, ADD_INCLUDE_PATH);
}

int dazukoAddExcludePath(const char *path)
{
	return dazukoAddExcludePath_TS(_GLOBAL_DAZUKO, path);
}

int dazukoAddExcludePath_TS(dazuko_id_t *dazuko_id, const char *path)
{
#if !defined(NO_COMPAT1)
	if (dazuko_id->comm_mode == DAZUKO_COMM_COMPAT1)
		return dazukoAddExcludePath_TS_compat1(dazuko_id, path);
#endif

	return dazuko_set_path(dazuko_id, path, ADD_EXCLUDE_PATH);
}

int dazukoRemoveAllPaths(void)
{
	return dazukoRemoveAllPaths_TS(_GLOBAL_DAZUKO);
}

int dazukoRemoveAllPaths_TS(dazuko_id_t *dazuko_id)
{
	struct dazuko_request	*request;
	size_t			size;
	char			buffer[ITOA_SIZE];

	if (dazuko_id == NULL)
		return -1;

#if !defined(NO_COMPAT1)
	if (dazuko_id->comm_mode == DAZUKO_COMM_COMPAT1)
		return dazukoRemoveAllPaths_TS_compat1(dazuko_id);
#endif

	if (dazuko_id->id < 0)
		return -1;

	if (xp_verify_id(dazuko_id) != 0)
		return -1;

	size = 1 + 2 + 1 + ITOA_SIZE /* \nID=id */
		+ 1 /* \0 */
		;

	request = alloc_request(REMOVE_ALL_PATHS, size, 0);
	if (request == NULL)
		return -1;

	snprintf(request->buffer, size, "\nID=%d", dazuko_id->id);
	request->buffer[size - 1] = 0;
	request->buffer_size = strlen(request->buffer) + 1;

	if (process_request(dazuko_id, buffer, sizeof(buffer), request, 0) != 0)
	{
		free_request(&request);
		return -1;
	}

	free_request(&request);

	return 0;
}

int dazukoGetAccess(struct dazuko_access **acc)
{
	return dazukoGetAccess_TS(_GLOBAL_DAZUKO, acc);
}

int dazukoGetAccess_TS(dazuko_id_t *dazuko_id, struct dazuko_access **acc)
{
	struct dazuko_request	*request;
	struct dazuko_access	*temp_acc;
	size_t			size;
	size_t			filename_size;
	char			buffer[ITOA_SIZE];
#if !defined(NO_COMPAT1)
	int			compat1_ret;
#endif

	if (dazuko_id == NULL)
		return -1;

#if !defined(NO_COMPAT1)
	if (dazuko_id->comm_mode == DAZUKO_COMM_COMPAT1)
	{
		compat1_ret = dazukoGetAccess_TS_compat1_wrapper(dazuko_id, acc);

		if (compat1_ret == 0 && !(dazuko_id->write_mode))
		{
			/* we are in read_only mode so we return the access immediately */

			dazukoReturnAccess_TS_compat1_wrapper(dazuko_id, acc, 1, 0);

			/* this could be dangerous, we do not check if the return was successfull! */
		}

		return compat1_ret;
	}
#endif

	if (dazuko_id->id < 0)
		return -1;

	if (xp_verify_id(dazuko_id) != 0)
		return -1;

	if (acc == NULL)
		return -1;

	size = 1 + 2 + 1 + ITOA_SIZE /* \nID=id */
		+ 1 /* \0 */
		;

	request = alloc_request(GET_AN_ACCESS, size,
		1 + 2 + 1 + DAZUKO_FILENAME_MAX_LENGTH /* \nFN=filename */
		+ 1024 /* miscellaneous access attributes */
		+ 1 /* \0 */
		);
	if (request == NULL)
		return -1;

	snprintf(request->buffer, size, "\nID=%d", dazuko_id->id);
	request->buffer[size - 1] = 0;
	request->buffer_size = strlen(request->buffer) + 1;

	temp_acc = (struct dazuko_access *)malloc(sizeof(struct dazuko_access));
	if (temp_acc == NULL)
	{
		free_request(&request);
		return -1;
	}

	memset(temp_acc, 0, sizeof(struct dazuko_access));

	filename_size = DAZUKO_FILENAME_MAX_LENGTH + 1;
	temp_acc->filename = (char *)malloc(filename_size);
	if (temp_acc->filename == NULL)
	{
		free(temp_acc);
		free_request(&request);
		return -1;
	}

	if (process_request(dazuko_id, buffer, sizeof(buffer), request, 1) != 0)
	{
		free(temp_acc->filename);
		free(temp_acc);
		free_request(&request);
		return -1;
	}

	if (request->reply_buffer_size_used > 0)
	{
		if (dazuko_get_value("\nFN=", request->reply_buffer, temp_acc->filename, filename_size) == 0)
		{
			temp_acc->set_filename = 1;
			unescape_string(temp_acc->filename);
		}

		if (dazuko_get_value("\nEV=", request->reply_buffer, buffer, sizeof(buffer)) == 0)
		{
			temp_acc->event = atoi(buffer);
			temp_acc->set_event = 1;
		}

		if (dazuko_get_value("\nFL=", request->reply_buffer, buffer, sizeof(buffer)) == 0)
		{
			temp_acc->flags = atoi(buffer);
			temp_acc->set_flags = 1;
		}

		if (dazuko_get_value("\nMD=", request->reply_buffer, buffer, sizeof(buffer)) == 0)
		{
			temp_acc->mode = atoi(buffer);
			temp_acc->set_mode = 1;
		}

		if (dazuko_get_value("\nUI=", request->reply_buffer, buffer, sizeof(buffer)) == 0)
		{
			temp_acc->uid = atoi(buffer);
			temp_acc->set_uid = 1;
		}

		if (dazuko_get_value("\nPI=", request->reply_buffer, buffer, sizeof(buffer)) == 0)
		{
			temp_acc->pid = atoi(buffer);
			temp_acc->set_pid = 1;
		}

		if (dazuko_get_value("\nFS=", request->reply_buffer, buffer, sizeof(buffer)) == 0)
		{
			temp_acc->file_size = atol(buffer);
			temp_acc->set_file_size = 1;
		}

		if (dazuko_get_value("\nFU=", request->reply_buffer, buffer, sizeof(buffer)) == 0)
		{
			temp_acc->file_uid = atoi(buffer);
			temp_acc->set_file_uid = 1;
		}

		if (dazuko_get_value("\nFG=", request->reply_buffer, buffer, sizeof(buffer)) == 0)
		{
			temp_acc->file_gid = atoi(buffer);
			temp_acc->set_file_gid = 1;
		}

		if (dazuko_get_value("\nDT=", request->reply_buffer, buffer, sizeof(buffer)) == 0)
		{
			temp_acc->file_device = atoi(buffer);
			temp_acc->set_file_device = 1;
		}

		if (dazuko_get_value("\nFM=", request->reply_buffer, buffer, sizeof(buffer)) == 0)
		{
			temp_acc->file_mode = atoi(buffer);
			temp_acc->set_file_mode = 1;
		}
	}

	free_request(&request);

	*acc = temp_acc;

	return 0;
}

int dazukoReturnAccess(struct dazuko_access **acc)
{
	return dazukoReturnAccess_TS(_GLOBAL_DAZUKO, acc);
}

int dazukoReturnAccess_TS(dazuko_id_t *dazuko_id, struct dazuko_access **acc)
{
	struct dazuko_request	*request;
	size_t			size;
	char			buffer[ITOA_SIZE];

	if (dazuko_id == NULL)
		return -1;

#if !defined(NO_COMPAT1)
	if (dazuko_id->comm_mode == DAZUKO_COMM_COMPAT1)
		return dazukoReturnAccess_TS_compat1_wrapper(dazuko_id, acc, dazuko_id->write_mode, 1);
#endif

	if (dazuko_id->id < 0)
		return -1;

	if (xp_verify_id(dazuko_id) != 0)
		return -1;

	if (acc == NULL)
		return -1;

	if (*acc == NULL)
		return -1;

	if (dazuko_id->write_mode)
	{
		size = 1 + 2 + 1 + ITOA_SIZE /* \nID=id */
			+ 1 + 2 + 1 + ITOA_SIZE /* \nDN=deny */
			+ 1 /* \0 */
			;

		request = alloc_request(RETURN_AN_ACCESS, size, 0);
		if (request == NULL)
			return -1;

		snprintf(request->buffer, size, "\nID=%d\nDN=%d", dazuko_id->id, (*acc)->deny == 0 ? 0 : 1);
		request->buffer[size - 1] = 0;
		request->buffer_size = strlen(request->buffer) + 1;

		if (process_request(dazuko_id, buffer, sizeof(buffer), request, 0) != 0)
		{
			/* there could be big problems if this happens */

			if ((*acc)->filename != NULL)
				free((*acc)->filename);
			free(*acc);
			*acc = NULL;
			free_request(&request);
			return -1;
		}

		free_request(&request);
	}

	if ((*acc)->filename != NULL)
		free((*acc)->filename);
	free(*acc);
	*acc = NULL;

	return 0;
}

int dazukoUnregister(void)
{
	return dazukoUnregister_TS(&_GLOBAL_DAZUKO);
}

int dazukoUnregister_TS(dazuko_id_t **dazuko_id)
{
	struct dazuko_request	*request;
	size_t			size;
	char			buffer[ITOA_SIZE];
	int			error = 0;

	if (dazuko_id == NULL)
		return -1;

	if (*dazuko_id == NULL)
		return -1;

#if !defined(NO_COMPAT1)
	if ((*dazuko_id)->comm_mode == DAZUKO_COMM_COMPAT1)
		return dazukoUnregister_TS_compat1_wrapper(dazuko_id);
#endif

	if (xp_verify_id(*dazuko_id) == 0)
	{
		size = 1 + 2 + 1 + ITOA_SIZE /* \nID=id */
			+ 1 /* \0 */
			;

		request = alloc_request(UNREGISTER, size, 0);
		if (request == NULL)
			return -1;

		snprintf(request->buffer, size, "\nID=%d", (*dazuko_id)->id);
		request->buffer[size - 1] = 0;
		request->buffer_size = strlen(request->buffer) + 1;

		if (process_request(*dazuko_id, buffer, sizeof(buffer), request, 0) != 0)
		{
			/* there could be big problems if this happens */

			error = -1;
		}

		free_request(&request);
	}

	xp_connection_close(*dazuko_id);
	free(*dazuko_id);
	*dazuko_id = NULL;

	return error;
}

int dazukoInitializeCache(struct dazuko_cache_settings *cs)
{
	return dazukoInitializeCache_TS(_GLOBAL_DAZUKO, cs);
}

int dazukoInitializeCache_TS(dazuko_id_t *dazuko_id, struct dazuko_cache_settings *cs)
{
	struct dazuko_request	*request;
	size_t			size;
	char			buffer[ITOA_SIZE];
	int			cache_available = 0;

	if (dazuko_id == NULL)
		return -1;

#if !defined(NO_COMPAT1)
	if (dazuko_id->comm_mode == DAZUKO_COMM_COMPAT1)
		return -1;
#endif

	if (dazuko_id->id < 0)
		return -1;

	if (xp_verify_id(dazuko_id) != 0)
		return -1;

	if (cs == NULL)
		return -1;

	size = 1 + 2 + 1 + ITOA_SIZE /* \nID=id */
		+ 1 + 2 + 1 + ITOA_SIZE /* \nCT=cachettl */
		+ 1 /* \0 */
		;

	request = alloc_request(INITIALIZE_CACHE, size,
		1 + 2 + 1 + ITOA_SIZE /* \nCA=cacheavailable */
		+ 1024 /* miscellaneous cache attributes */
		+ 1 /* \0 */
		);
	if (request == NULL)
		return -1;

	snprintf(request->buffer, size, "\nID=%d\nCT=%lu", dazuko_id->id, cs->ttl);
	request->buffer[size - 1] = 0;
	request->buffer_size = strlen(request->buffer) + 1;

	if (process_request(dazuko_id, buffer, sizeof(buffer), request, 1) != 0)
	{
		free_request(&request);
		return -1;
	}

	if (request->reply_buffer_size_used > 0)
	{
		if (dazuko_get_value("\nCA=", request->reply_buffer, buffer, sizeof(buffer)) == 0)
		{
			cache_available = atoi(buffer);
		}
	}

	free_request(&request);

	if (cache_available)
		return 0;

	return -1;
}

int dazukoRemoveAllTrusted(void)
{
	return dazukoRemoveAllTrusted_TS(_GLOBAL_DAZUKO);
}

int dazukoRemoveAllTrusted_TS(dazuko_id_t *dazuko_id)
{
	struct dazuko_request	*request;
	size_t			size;
	char			buffer[ITOA_SIZE];

	if (dazuko_id == NULL)
		return -1;

#if !defined(NO_COMPAT1)
	if (dazuko_id->comm_mode == DAZUKO_COMM_COMPAT1)
		return -1;
#endif

	if (dazuko_id->id < 0)
		return -1;

	if (xp_verify_id(dazuko_id) != 0)
		return -1;

	size = 1 + 2 + 1 + ITOA_SIZE /* \nID=id */
		+ 1 /* \0 */
		;

	request = alloc_request(REMOVE_ALL_TRUSTED, size, 0);
	if (request == NULL)
		return -1;

	snprintf(request->buffer, size, "\nID=%d", dazuko_id->id);
	request->buffer[size - 1] = 0;
	request->buffer_size = strlen(request->buffer) + 1;

	if (process_request(dazuko_id, buffer, sizeof(buffer), request, 0) != 0)
	{
		free_request(&request);
		return -1;
	}

	free_request(&request);

	return 0;
}

int dazukoRemoveTrusted(const char *token)
{
	return dazukoRemoveTrusted_TS(_GLOBAL_DAZUKO, token);
}

int dazukoRemoveTrusted_TS(dazuko_id_t *dazuko_id, const char *token)
{
	struct dazuko_request	*request;
	size_t			size;
	char			buffer[ITOA_SIZE];

	if (dazuko_id == NULL || token == NULL)
		return -1;

#if !defined(NO_COMPAT1)
	if (dazuko_id->comm_mode == DAZUKO_COMM_COMPAT1)
		return -1;
#endif

	if (dazuko_id->id < 0)
		return -1;

	if (xp_verify_id(dazuko_id) != 0)
		return -1;

	size = 1 + 2 + 1 + ITOA_SIZE /* \nID=id */
		+ 1 + 2 + 1 + strlen(token) /* \nTT=token */
		+ 1 /* \0 */
		;

	request = alloc_request(REMOVE_TRUSTED, size, 0);
	if (request == NULL)
		return -1;

	snprintf(request->buffer, size, "\nID=%d\nTT=%s", dazuko_id->id, token);
	request->buffer[size - 1] = 0;
	request->buffer_size = strlen(request->buffer) + 1;

	if (process_request(dazuko_id, buffer, sizeof(buffer), request, 0) != 0)
	{
		free_request(&request);
		return -1;
	}

	free_request(&request);

	return 0;
}

