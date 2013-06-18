/* Dazuko FreeBSD. Allow FreeBSD file access control for 3rd-party applications.
   Written by John Ogness <dazukocode@ogness.net>

   Copyright (c) 2003, 2004, 2005, 2006 H+BEDV Datentechnik GmbH
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

#ifndef DAZUKO_FREEBSD_H
#define DAZUKO_FREEBSD_H

#include <sys/param.h>
#include <sys/libkern.h>
#include <sys/lock.h>
#include <machine/stdarg.h>


#define inline		__inline
#define	DEVICE_NAME	"dazuko"

#define XP_ERROR_PERMISSION	EPERM
#define XP_ERROR_INTERRUPT	EINTR
#define XP_ERROR_BUSY		EBUSY
#define XP_ERROR_FAULT		EFAULT
#define XP_ERROR_INVALID	EINVAL


struct xp_daemon_id
{
	int		pid;
	struct proc	*proc;
	struct filedesc	*fd;
};

struct xp_mutex
{
	struct simplelock	lock;
};

struct xp_atomic
{
	int	value;
};

struct xp_file_struct
{
	const char	*user_filename;
	struct proc	*p;
	int		fd;
};

struct xp_queue
{
	char	c;
};

struct xp_rwlock
{
	struct lock	lock;
};

#endif
