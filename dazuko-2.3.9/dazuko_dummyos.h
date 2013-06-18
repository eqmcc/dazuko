/* Dazuko Dummy. A dummy implementation to help porting to new platforms.
   Written by John Ogness <dazukocode@ogness.net>

   Copyright (c) 2004, 2005, 2006 H+BEDV Datentechnik GmbH
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

#ifndef DAZUKO_DUMMYOS_H
#define DAZUKO_DUMMYOS_H


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>


#define XP_ERROR_PERMISSION	-1
#define XP_ERROR_INTERRUPT	-2
#define XP_ERROR_BUSY		-3
#define XP_ERROR_FAULT		-4
#define XP_ERROR_INVALID	-5


struct xp_daemon_id
{
	int	id;
};

struct xp_mutex
{
	pthread_mutex_t	mutex;
};

struct xp_atomic
{
	int	atomic;
};

struct xp_file_struct
{
	const char	*user_filename;
};

struct xp_queue
{
	pthread_cond_t	condition;
	pthread_mutex_t	mutex;
};

struct xp_rwlock
{
	pthread_mutex_t	rwlock;
};

#endif
