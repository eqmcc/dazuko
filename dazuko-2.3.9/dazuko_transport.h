/* Dazuko Transport. Types shared between userspace and kernelspace.
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

#ifndef DAZUKOIO_TRANSPORT_H
#define DAZUKOIO_TRANSPORT_H

/* various requests */
#define SET_ACCESS_MASK		0
#define ADD_INCLUDE_PATH	1
#define ADD_EXCLUDE_PATH	2
#define REGISTER		3
#define REMOVE_ALL_PATHS	4
#define UNREGISTER		5
#define GET_AN_ACCESS		6
#define RETURN_AN_ACCESS	7
#define INITIALIZE_CACHE	8
#define REGISTER_TRUSTED	9
#define UNREGISTER_TRUSTED	10
#define REMOVE_ALL_TRUSTED	11
#define REMOVE_TRUSTED		12

/* this is the hard-limit file length restriction from
   the 1.x series */
#define DAZUKO_FILENAME_MAX_LENGTH_COMPAT1	4095

struct dazuko_request
{
	char	type[2];
	int	buffer_size;
	char	*buffer;
	int	reply_buffer_size;
	char	*reply_buffer;
	int	reply_buffer_size_used;
};

/* get the size a low level representation can use in maximum */
int dazuko_reqstream_dim_chunk0(int size_chr, int size_int, int size_ptr);

/* get the chunksize for the given low level representation (represented in the first 4 bytes) */
int dazuko_reqstream_chunksize(unsigned char *ll, int *size);

/* convert from high level to low level and vice versa */
int dazuko_reqstream_hl2ll(struct dazuko_request *req, unsigned char *ll);
int dazuko_reqstream_ll2hl(unsigned char *ll, struct dazuko_request *req, int strict);

/* update (patch) a low level stream from its high level template */
int dazuko_reqstream_updll(struct dazuko_request *req, unsigned char *ll);

/* compat1 ioctls */

#define	IOCTL_SET_OPTION	0
#define	IOCTL_GET_AN_ACCESS	1
#define	IOCTL_RETURN_ACCESS	2

/* compat1 structures */

struct access_compat1
{
	int	deny;		/* set to deny file access */
	int	event;		/* ON_OPEN, etc */
	int	o_flags;	/* access flags */
	int	o_mode;		/* access mode */
	int	uid;		/* user id */
	int	pid;		/* user process id */
	char	filename[DAZUKO_FILENAME_MAX_LENGTH_COMPAT1];	/* accessed file */
};

struct option_compat1
{
	int	command;
	int	buffer_length;
	char	buffer[DAZUKO_FILENAME_MAX_LENGTH_COMPAT1];
};

#endif
