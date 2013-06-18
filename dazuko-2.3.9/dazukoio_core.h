/* DazukoXP Interface. Interace with Dazuko for file access control.
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

#ifndef DAZUKOIO_XP_H
#define DAZUKOIO_XP_H

#include <stdio.h>
#include "dazukoio_platform.h"
#include "dazuko_transport.h"

/* this should be big enough for the biggest number string + 4 */
#define ITOA_SIZE	64

/* various communication modes */
#define DAZUKO_COMM_UNSET	0
#define DAZUKO_COMM_COMPAT1	1
#define DAZUKO_COMM_DEVWRITE	2
#define DAZUKO_COMM_REQSTREAM	3

struct dazuko_id
{
	int			id;
	int			write_mode;
	int			comm_mode;
	struct xp_dazukoio_id	*extra_data;  /* this must be defined in platform implementation */
};

/* connection to Dazuko (implemented by extensions) */
int xp_connection_open(struct dazuko_id *id);
int xp_connection_close(struct dazuko_id *id);

/* verify id validity (implemented by extensions) */
int xp_verify_id(struct dazuko_id *id);

/* process requests (implemented by extensions) */
int xp_process_request(struct dazuko_id *id, const char *buffer, size_t buffer_size);

/* functions available to extensions */
int dazuko_get_value(const char *key, const char *string, char *buffer, size_t buffer_size);
int process_request(struct dazuko_id *id, char *buffer, size_t buffer_size, struct dazuko_request *request, int reply_required);

#endif
