/* ----- IO.xs ----------------------------------------------- */
/* Perl extension for Dazuko, XS part */

/*
 * Copyright (c) 2004, 2005 Gerhard Sittig
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of Dazuko nor the names of its contributors may be used
 * to endorse or promote products derived from this software without specific
 * prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <dazukoio.h>

MODULE = Dazuko::IO	PACKAGE = Dazuko::IO	PREFIX = dazuko
 
PROTOTYPES: ENABLE

BOOT:
/* { ----- thread unaware routines ----- */

int
dazukoRegister(group, mode)
	char *group
	char *mode
OUTPUT:
	RETVAL

int
dazukoUnregister()
OUTPUT:
	RETVAL

int
dazukoSetAccessMask(mask)
	int mask
OUTPUT:
	RETVAL

int
dazukoAddIncludePath(path)
	char *path
OUTPUT:
	RETVAL

int
dazukoAddExcludePath(path)
	char *path
OUTPUT:
	RETVAL

int
dazukoRemoveAllPaths()
OUTPUT:
	RETVAL

void
dazukoGetAccess()
PREINIT:
	/*
	 * this one needs some more attention -- it is not merely
	 * an XS wrapped C routine but instead returns the
	 * fields of the "struct dazuko_access" structure in a
	 * Perl style list (or "undef" in case of failure)
	 */
	struct dazuko_access *acc;
	int rc;
	SV *undef;
PPCODE:
	/* place an "undef" as (default) RETVAL */
	ST(0) = sv_newmortal();
	/* invoke the C routine */
	acc = NULL;
	rc = dazukoGetAccess(&acc);
	if (rc != 0) {
		/* no access -> return(undef) */
		/* EMPTY */
	} else if (acc == NULL) {
		/* no data -> return(undef) */
		/* EMPTY */
	} else if (! acc->event) {
		/* no event -> ReturnAccess(), return(undef) */
		dazukoReturnAccess(&acc);
	} else {
		/* otherwise return($acc, $deny, $event, ...) */
		undef = &PL_sv_undef;	/* shortcut */
		EXTEND(SP, 13);
		PUSHs(sv_2mortal(newSViv(PTR2IV(acc))));
		PUSHs(sv_2mortal(newSViv(acc->deny)));
		PUSHs(acc->set_event ? sv_2mortal(newSViv(acc->event)) : undef);
		PUSHs(acc->set_flags ? sv_2mortal(newSViv(acc->flags)) : undef);
		PUSHs(acc->set_mode ? sv_2mortal(newSViv(acc->mode)) : undef);
		PUSHs(acc->set_uid ? sv_2mortal(newSViv(acc->uid)) : undef);
		PUSHs(acc->set_pid ? sv_2mortal(newSViv(acc->pid)) : undef);
		PUSHs(acc->set_filename ? sv_2mortal(newSVpv(acc->filename, strlen(acc->filename))) : undef);
		PUSHs(acc->set_file_size ? sv_2mortal(newSViv(acc->file_size)) : undef);
		PUSHs(acc->set_file_uid ? sv_2mortal(newSViv(acc->file_uid)) : undef);
		PUSHs(acc->set_file_gid ? sv_2mortal(newSViv(acc->file_gid)) : undef);
		PUSHs(acc->set_file_mode ? sv_2mortal(newSViv(acc->file_mode)) : undef);
		PUSHs(acc->set_file_device ? sv_2mortal(newSViv(acc->file_device)) : undef);
		/* adjust the above EXTEND() when you add more items to the list */
	}

int
dazukoReturnAccess(ref, deny = 0)
	IV ref
	int deny
PREINIT:
	struct dazuko_access *acc;
CODE:
	acc = INT2PTR(struct dazuko_access *, ref);
	acc->deny = deny;
	RETVAL = dazukoReturnAccess(&acc);
OUTPUT:
	RETVAL

void
dazukoVersion()
PREINIT:
	/*
	 * get the struct from the C library,
	 * pass an array up to the Perl caller
	 */
	struct dazuko_version ver;
PPCODE:
	memset(&ver, 0, sizeof(ver));
	if (dazukoVersion(&ver) != 0) {
		ST(0) = sv_newmortal();
	} else {
		EXTEND(SP, 5);
		PUSHs(sv_2mortal(newSVpv(ver.text, strlen(ver.text))));
		PUSHs(sv_2mortal(newSViv(ver.major)));
		PUSHs(sv_2mortal(newSViv(ver.minor)));
		PUSHs(sv_2mortal(newSViv(ver.revision)));
		PUSHs(sv_2mortal(newSViv(ver.release)));
		/* adjust the above EXTEND() when you add more items to the list */
	}

void
dazukoIOVersion()
PREINIT:
	/*
	 * get the struct from the C library,
	 * pass an array up to the Perl caller
	 */
	struct dazuko_version ver;
PPCODE:
	memset(&ver, 0, sizeof(ver));
	if (dazukoIOVersion(&ver) != 0) {
		ST(0) = sv_newmortal();
	} else {
		EXTEND(SP, 5);
		PUSHs(sv_2mortal(newSVpv(ver.text, strlen(ver.text))));
		PUSHs(sv_2mortal(newSViv(ver.major)));
		PUSHs(sv_2mortal(newSViv(ver.minor)));
		PUSHs(sv_2mortal(newSViv(ver.revision)));
		PUSHs(sv_2mortal(newSViv(ver.release)));
		/* adjust the above EXTEND() when you add more items to the list */
	}

BOOT:
/* } ----- end of thread unaware routines ----- */
/* { ----- thread safe routines ----- */

void
dazukoRegister_TS(group, mode)
	char *group
	char *mode
PREINIT:
	dazuko_id_t *idp;
	int rc;
PPCODE:
	/* place an "undef" as the return value */
	ST(0) = sv_newmortal();
	/* call the register routine */
	idp = NULL;
	rc = dazukoRegister_TS(&idp, group, mode);
	/* return $id if we succeeded to register */
	if (rc == 0) {
		EXTEND(SP, 1);
		PUSHs(sv_2mortal(newSViv(PTR2IV(idp))));
	}

int
dazukoUnregister_TS(id)
	IV id
PREINIT:
	dazuko_id_t *idp;
CODE:
	idp = INT2PTR(dazuko_id_t *, id);
	RETVAL = dazukoUnregister_TS(&idp);
OUTPUT:
	RETVAL

int
dazukoSetAccessMask_TS(id, mask)
	IV id
	int mask
PREINIT:
	dazuko_id_t *idp;
CODE:
	idp = INT2PTR(dazuko_id_t *, id);
	RETVAL = dazukoSetAccessMask_TS(idp, mask);
OUTPUT:
	RETVAL

int
dazukoAddIncludePath_TS(id, path)
	IV id
	char *path
PREINIT:
	dazuko_id_t *idp;
CODE:
	idp = INT2PTR(dazuko_id_t *, id);
	RETVAL = dazukoAddIncludePath_TS(idp, path);
OUTPUT:
	RETVAL

int
dazukoAddExcludePath_TS(id, path)
	IV id
	char *path
PREINIT:
	dazuko_id_t *idp;
CODE:
	idp = INT2PTR(dazuko_id_t *, id);
	RETVAL = dazukoAddExcludePath_TS(idp, path);
OUTPUT:
	RETVAL

int
dazukoRemoveAllPaths_TS(id)
	IV id
PREINIT:
	dazuko_id_t *idp;
CODE:
	idp = INT2PTR(dazuko_id_t *, id);
	RETVAL = dazukoRemoveAllPaths_TS(idp);
OUTPUT:
	RETVAL

void
dazukoGetAccess_TS(id)
	IV id
PREINIT:
	/*
	 * this one needs some more attention -- it is not merely
	 * an XS wrapped C routine but instead returns the
	 * fields of the "struct dazuko_access" structure in a
	 * Perl style list (or "undef" in case of failure)
	 */
	dazuko_id_t *idp;
	struct dazuko_access *acc;
	int rc;
	SV *undef;
PPCODE:
	idp = INT2PTR(dazuko_id_t *, id);
	/* place an "undef" as (default) RETVAL */
	ST(0) = sv_newmortal();
	/* invoke the C routine */
	acc = NULL;
	rc = dazukoGetAccess_TS(idp, &acc);
	if (rc != 0) {
		/* no access -> return(undef) */
		/* EMPTY */
	} else if (acc == NULL) {
		/* no data -> return(undef) */
		/* EMPTY */
	} else if (! acc->event) {
		/* no event -> ReturnAccess(), return(undef) */
		dazukoReturnAccess(&acc);
	} else {
		/* otherwise return($acc, $deny, $event, ...) */
		undef = &PL_sv_undef;	/* shortcut */
		EXTEND(SP, 13);
		PUSHs(sv_2mortal(newSViv(PTR2IV(acc))));
		PUSHs(sv_2mortal(newSViv(acc->deny)));
		PUSHs(acc->set_event ? sv_2mortal(newSViv(acc->event)) : undef);
		PUSHs(acc->set_flags ? sv_2mortal(newSViv(acc->flags)) : undef);
		PUSHs(acc->set_mode ? sv_2mortal(newSViv(acc->mode)) : undef);
		PUSHs(acc->set_uid ? sv_2mortal(newSViv(acc->uid)) : undef);
		PUSHs(acc->set_pid ? sv_2mortal(newSViv(acc->pid)) : undef);
		PUSHs(acc->set_filename ? sv_2mortal(newSVpv(acc->filename, strlen(acc->filename))) : undef);
		PUSHs(acc->set_file_size ? sv_2mortal(newSViv(acc->file_size)) : undef);
		PUSHs(acc->set_file_uid ? sv_2mortal(newSViv(acc->file_uid)) : undef);
		PUSHs(acc->set_file_gid ? sv_2mortal(newSViv(acc->file_gid)) : undef);
		PUSHs(acc->set_file_mode ? sv_2mortal(newSViv(acc->file_mode)) : undef);
		PUSHs(acc->set_file_device ? sv_2mortal(newSViv(acc->file_device)) : undef);
		/* adjust the above EXTEND() when you add more items to the list */
	}

int
dazukoReturnAccess_TS(id, ref, deny = 0)
	IV id
	IV ref
	int deny
PREINIT:
	dazuko_id_t *idp;
	struct dazuko_access *acc;
CODE:
	idp = INT2PTR(dazuko_id_t *, id);
	acc = INT2PTR(struct dazuko_access *, ref);
	acc->deny = deny;
	RETVAL = dazukoReturnAccess_TS(idp, &acc);
OUTPUT:
	RETVAL

BOOT:
/* } ----- end of thread safe routines ----- */

BOOT:
/* ----- E O F ----------------------------------------------- */
