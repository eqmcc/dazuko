/* Dazuko Interface. Interace with Dazuko for file access control.
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

#ifndef DAZUKOIO_H
#define DAZUKOIO_H

#include "dazuko_events.h"

struct dazuko_access
{
	int		deny;
	int		event;
	char		set_event;
	int		flags;
	char		set_flags;
	int		mode;
	char		set_mode;
	int 		uid;
	char		set_uid;
	int		pid;
	char		set_pid;
	char		*filename;
	char		set_filename;
	unsigned long	file_size;
	char		set_file_size;
	int		file_uid;
	char		set_file_uid;
	int		file_gid;
	char		set_file_gid;
	int		file_mode;
	char		set_file_mode;
	int		file_device;
	char		set_file_device;
};

struct dazuko_cache_settings
{
	unsigned long	ttl;
};

#define DAZUKO_VERSION_TEXT_SIZE 64

struct dazuko_version
{
	int	major;
	int	minor;
	int	revision;
	int	release;
	char	text[DAZUKO_VERSION_TEXT_SIZE];
};

struct dazuko_id;
typedef struct dazuko_id dazuko_id_t;

/* version API */
int dazukoVersion(struct dazuko_version *version);
int dazukoIOVersion(struct dazuko_version *version);

/* single-threaded API */
int dazukoRegister(const char *groupName, const char *mode);
int dazukoSetAccessMask(unsigned long accessMask);
int dazukoAddIncludePath(const char *path);
int dazukoAddExcludePath(const char *path);
int dazukoRemoveAllPaths(void);
int dazukoGetAccess(struct dazuko_access **acc);
int dazukoReturnAccess(struct dazuko_access **acc);
int dazukoUnregister(void);
int dazukoInitializeCache(struct dazuko_cache_settings *cs);
int dazukoRemoveAllTrusted(void);
int dazukoRemoveTrusted(const char *token);

/* thread-safe API (as long as each thread has its own "dazuko_id_t") */
int dazukoRegister_TS(dazuko_id_t **dazuko_id, const char *groupName, const char *mode);
int dazukoSetAccessMask_TS(dazuko_id_t *dazuko_id, unsigned long accessMask);
int dazukoAddIncludePath_TS(dazuko_id_t *dazuko_id, const char *path);
int dazukoAddExcludePath_TS(dazuko_id_t *dazuko_id, const char *path);
int dazukoRemoveAllPaths_TS(dazuko_id_t *dazuko_id);
int dazukoGetAccess_TS(dazuko_id_t *dazuko_id, struct dazuko_access **acc);
int dazukoReturnAccess_TS(dazuko_id_t *dazuko_id, struct dazuko_access **acc);
int dazukoUnregister_TS(dazuko_id_t **dazuko_id);
int dazukoInitializeCache_TS(dazuko_id_t *dazuko_id, struct dazuko_cache_settings *cs);
int dazukoRemoveAllTrusted_TS(dazuko_id_t *dazuko_id);
int dazukoRemoveTrusted_TS(dazuko_id_t *dazuko_id, const char *token);

#endif
