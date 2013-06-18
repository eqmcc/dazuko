/* ----- libdazuko.c ----------------------------------------- */

/*
 * lua extension to interface with Dazuko
 */

/*
 * Copyright (c) 2005-2007 Gerhard Sittig
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

/*
 * example usage:
 *
 *   require "dazuko"
 *
 *   function dump(acc)
 *     -- table.foreach(acc, print)
 *     print(acc['filename'])
 *     return 0
 *   end
 *
 *   d = dazuko.new("vendor:app", "r")
 *   print(d:version()['text'])
 *   print(d:ioversion()['text'])
 *   d:setaccessmask(dazuko.ON_OPEN + dazuko.ON_CLOSE)
 *   d:addincludepath("/home", "/export", "/media")
 *   d:addexcludepath("/proc", "/dev")
 *
 *   while (d:getaccess(dump)) do
 *     -- EMPTY
 *   end
 *
 *   d:unregister()
 *   d = nil
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#include <dazukoio.h>

#if defined DEBUG
  #define dbg(x) printf x;
#else
  #define dbg(x) /* EMPTY */
#endif


/*
 * TODO:
 * - split the registration from the constructor, give it an own method?
 * - make the registration in the contructor optional?  this of course only
 *   applies when there is a separate registration method
 * - how to ship documentation with this library source?  ldoc(1) or doxygen or
 *   a dazuko.__doc multi line string?
 * - can the build setup be improved?  instead of "documenting" that "you have
 *   to adjust the example Makefile to fit your needs"
 */

#define MODULE_NAME "dazuko"
#define METATABLE_NAME "dazuko"

/*
 * private userdata for the object,
 * don't expose registered dazuko ID and held access to the application,
 * optionally add safety belts and API violation warnings
 */
struct dazuko_object {
	dazuko_id_t *id;
	struct dazuko_access *acc;
	int ro;
};

/*
 * new() constructor, registers with the kernel,
 * receives the group name and an optional mode string,
 * returns the object to subsequently work with
 */
static int dazuko_new(lua_State *L) {
	const char *group, *mode;
	struct dazuko_object *self;
	int rc;

	dbg(("dazuko.new()\n"))

	/* get the group (mandatory) and the mode (optional) */
	group = luaL_checkstring(L, 1);
	luaL_argcheck(L, (group != NULL) && (*group != '\0'), 1, "invalid group spec");
	mode = luaL_optlstring(L, 2, "r", NULL);
	luaL_argcheck(L, (mode != NULL) && (*mode != '\0'), 1, "invalid mode spec");

	/* create a userdata object */
	self = lua_newuserdata(L, sizeof(*self));
	luaL_getmetatable(L, METATABLE_NAME);
	lua_setmetatable(L, -2);

	/* start with empty settings */
	memset(self, 0, sizeof(*self));
	self->id = NULL;
	self->acc = NULL;
	self->ro = 0;

	/* register with the kernel -- make this optional or always a separate method? */
	dbg(("calling dazukoRegister_TS(&%p, \"%s\", \"%s\")", self->id, group, mode))
	rc = dazukoRegister_TS(&self->id, group, mode);
	dbg((" => rc %d, id %p\n", rc, self->id))
	if ((rc == 0) && (self->id != NULL)) {
		self->ro = (strcmp(mode, "r") == 0) ? 1 : 0;
	}

	/* XXX
	 * do we want to bail out on errors or
	 * do we just return an "ususable" object?
	 */
	if ((rc != 0) || (self->id == NULL)) {
		luaL_error(L, "cannot register with the kernel");
	}

	return(1);
}

/*
 * common routine to get version info,
 * returns a table with version number parts and a text representation
 */
static int dazuko_getversion_common(lua_State *L, int (*func)(struct dazuko_version *)) {
	struct dazuko_version ver;
	int rc;

	/* call dazuko function */
	memset(&ver, 0, sizeof(ver));
	dbg(("calling dazuko*Version()"))
	rc = func(&ver);
	dbg((" => rc %d\n", rc))

	/* bail out upon error */
	if (rc != 0) {
		lua_pushnil(L);
		return(1);
	}

	/* return a table upon success */
	lua_newtable(L);
	lua_pushstring(L, ver.text);
	lua_setfield(L, -2, "text");
	lua_pushnumber(L, ver.major);
	lua_setfield(L, -2, "major");
	lua_pushnumber(L, ver.minor);
	lua_setfield(L, -2, "minor");
	lua_pushnumber(L, ver.revision);
	lua_setfield(L, -2, "revision");
	lua_pushnumber(L, ver.release);
	lua_setfield(L, -2, "release");
	return(1);
}

/*
 * version() routine/method, queries the kernel module version,
 * receives nothing (well, expects nothing),
 * returns a table
 */
static int dazuko_version(lua_State *L) {
	return(dazuko_getversion_common(L, dazukoVersion));
}

/*
 * ioversion() routine/method, queries the IO library version,
 * receives nothing (well, expects nothing),
 * returns a table
 */
static int dazuko_ioversion(lua_State *L) {
	return(dazuko_getversion_common(L, dazukoIOVersion));
}

/*
 * setaccessmask() method, configures wanted events,
 * receives the object and the mask,
 * returns a boolean
 */
static int dazuko_setaccessmask(lua_State *L) {
	struct dazuko_object *self;
	int mask;
	int rc;

	dbg(("dazuko.setaccessmask()\n"))

	self = luaL_checkudata(L, 1, METATABLE_NAME);
	luaL_argcheck(L, self != NULL, 1, "'dazuko' object expected");
	mask = luaL_checkint(L, 2);

	dbg(("calling dazukoSetAccessMask_TS(%p, %d)", self->id, mask))
	rc = dazukoSetAccessMask_TS(self->id, mask);
	dbg((" => rc %d, id %p\n", rc, self->id))

	lua_pushboolean(L, (rc == 0) ? 1 : 0);
	return(1);
}

/*
 * common routine to add path specs (include, exclude paths)
 */
static int dazuko_addpath_common(lua_State *L, int (*func)(dazuko_id_t *, const char *)) {
	struct dazuko_object *self;
	int argc;
	int idx;
	const char *path;
	int rc;
	int res;

	self = luaL_checkudata(L, 1, METATABLE_NAME);
	luaL_argcheck(L, self != NULL, 1, "'dazuko' object expected");

	/*
	 * check arguments (path specs are completely optional but need to
	 * be non empty if present; absolute specs are not enforced here)
	 */
	argc = lua_gettop(L);
	for (idx = 2; idx <= argc; idx++) {
		path = luaL_checkstring(L, idx);
		luaL_argcheck(L, (path != NULL) && (*path != '\0'), idx, "empty path spec");
	}

	/* call dazuko function */
	res = 0;
	for (idx = 2; idx <= argc; idx++) {
		path = lua_tostring(L, idx);
		dbg(("calling dazukoAdd*Path_TS(%p, \"%s\")", self->id, path))
		rc = func(self->id, path);
		dbg((" => rc %d\n", rc))
		if (rc != 0) {
			/* only this path failed, keep passing the others */
			res = -1;
		}
	}

	/* return success */
	lua_pushboolean(L, (res == 0) ? 1 : 0);
	return(1);
}

/*
 * addincludepath() method, adds another directory to supervise,
 * receives the object and a (list of) string(s),
 * returns a boolean
 */
static int dazuko_addincludepath(lua_State *L) {
	return(dazuko_addpath_common(L, dazukoAddIncludePath_TS));
}

/*
 * addexcludepath() method, adds another directory to ignore,
 * receives the object and a (list of) string(s),
 * returns a boolean
 */
static int dazuko_addexcludepath(lua_State *L) {
	return(dazuko_addpath_common(L, dazukoAddExcludePath_TS));
}

/*
 * removeallpaths() method, clears the include and exclude paths lists,
 * receives the object,
 * returns a boolean
 */
static int dazuko_removeallpaths(lua_State *L) {
	struct dazuko_object *self;
	int rc;

	self = luaL_checkudata(L, 1, METATABLE_NAME);
	luaL_argcheck(L, self != NULL, 1, "'dazuko' object expected");

	dbg(("calling dazukoRemoveAllPaths_TS(%p)", self->id))
	rc = dazukoRemoveAllPaths_TS(self->id);
	dbg((" => rc %d\n", rc))

	lua_pushboolean(L, (rc == 0) ? 1 : 0);
	return(1);
}

/*
 * getaccess() method, waits for an event and has it handled, may deny access,
 * receives the object and a function (plus optional additional arguments),
 * returns a boolean
 *
 * when a file access event becomes available, the specified routine is called
 * with the access details as the first parameter; optional excess parameters
 * passed to this method are passed to the handler routine after the first
 * access details table parameter; the handler routine's return code specifies
 * whether to grant (nil, false, zero) or to deny (true, non zero) the access
 *
 * failure to get an event as well as failure to run the handler routine or to
 * evaluate its return code all are signalled by a non successful return code
 *
 * BEWARE!  while the handler routine is run, the kernel is waiting for you,
 * holding the file access until the decision is made whether to grant or
 * deny the access -- so make sure you spend as little time as necessary
 * in that condition;  and be aware of the great responsibility you accept
 * for the system's stability by writing a dazuko enabled application
 */
static int dazuko_getaccess(lua_State *L) {
	struct dazuko_object *self;
	int argc;
	int rc;
	int idx;
	int prevdeny;
	int res;

	self = luaL_checkudata(L, 1, METATABLE_NAME);
	luaL_argcheck(L, self != NULL, 1, "'dazuko' object expected");
	luaL_checktype(L, 2, LUA_TFUNCTION);
	argc = lua_gettop(L); /* for the below excess callback arguments */

	/* this is an API violation */
	if (self->acc != NULL) {
		fprintf(stderr, "BEWARE! getting another access while still holding one\n");
		/* is luaL_error() more appropriate here? */
		lua_pushboolean(L, 0);
		return(1);
	}

	/* call dazuko function to get an access */
	dbg(("calling dazukoGetAccess_TS(%p, &%p)", self->id, self->acc)) fflush(stdout);
	rc = dazukoGetAccess_TS(self->id, &self->acc);
	dbg((" => rc %d, acc %p\n", rc, self->acc))
	if (rc != 0) {
		dbg(("error getting access\n"))
		lua_pushboolean(L, 0);
		return(1);
	} else if (self->acc == NULL) {
		dbg(("got no access\n"))
		lua_pushboolean(L, 0);
		return(1);
	} else if (self->acc->event == 0) {
		dbg(("got no event\n"))
		rc = dazukoReturnAccess_TS(self->id, &self->acc);
		lua_pushboolean(L, 0);
		return(1);
	}
	dbg(("got event, collecting data"))

	/* prepare access details for the handler */
	lua_pushvalue(L, 2); /* handler function */
#define IF_SET(key) \
	if (self->acc->set_ ##key)
#define ADD_DETAIL_I(key) do { \
	lua_pushnumber(L, self->acc->key); \
	lua_setfield(L, -2, #key); \
} while(0)
#define ADD_DETAIL_S(key) do { \
	lua_pushstring(L, self->acc->key); \
	lua_setfield(L, -2, #key); \
} while(0)
	lua_newtable(L); /* access details */
	ADD_DETAIL_I(deny);
	IF_SET(event) ADD_DETAIL_I(event);
	IF_SET(flags) ADD_DETAIL_I(flags);
	IF_SET(mode) ADD_DETAIL_I(mode);
	IF_SET(uid) ADD_DETAIL_I(uid);
	IF_SET(pid) ADD_DETAIL_I(pid);
	IF_SET(filename) ADD_DETAIL_S(filename);
	IF_SET(file_size) ADD_DETAIL_I(file_size);
	IF_SET(file_uid) ADD_DETAIL_I(file_uid);
	IF_SET(file_gid) ADD_DETAIL_I(file_gid);
	IF_SET(file_mode) ADD_DETAIL_I(file_mode);
	IF_SET(file_device) ADD_DETAIL_I(file_device);
#undef IF_SET
#undef ADD_DETAIL_I
#undef ADD_DETAIL_S

	/* as a friendly service: pass all excess params to the handler */
	for (idx = 3; idx <= argc; idx++) {
		lua_pushvalue(L, idx);
	}

	/* call the handler */
	prevdeny = self->acc->deny;
	dbg((", calling handler\n"))
	rc = lua_pcall(L, 1 + (argc - 2), 1, 0);

	/* determine deny state */
	/* XXX make this warning output the error code for the caller? */
	res = 0;
	if (rc != 0) {
		const char *err;
		err = lua_tostring(L, -1);
		fprintf(stderr, "error in access handler [%s], will grant access\n", err);
		self->acc->deny = 0;
		res = -1;
	} else if (lua_isnil(L, -1)) {
		self->acc->deny = 0;
	} else if (lua_isboolean(L, -1)) {
		int b;
		b = lua_toboolean(L, -1);
		self->acc->deny = (b) ? 1 : 0;
	} else if (lua_isnumber(L, -1)) {
		int n;
		n = lua_tonumber(L, -1);
		self->acc->deny = (n != 0) ? 1 : 0;
	} else {
		fprintf(stderr, "unknown return type from access handler (%d), will grant access\n", lua_type(L, -1));
		self->acc->deny = 0;
		res = -1;
	}
	/* issue a warning, I know how hard it is to find that kind of error :) */
	if ((self->acc->deny) && (self->acc->deny != prevdeny) && (self->ro)) {
		fprintf(stderr, "BEWARE! trying to deny in read-only mode\n");
		res = -1;
	}

	/* return access to the kernel */
	dbg(("calling dazukoReturnAccess_TS(%p, &%p), deny %d"
			, self->id, self->acc, self->acc->deny
			))
	rc = dazukoReturnAccess_TS(self->id, &self->acc);
	dbg((" => rc %d\n", rc))

	/* return success */
	lua_pushboolean(L, (res == 0) ? 1 : 0);
	return(1);
}

/*
 * unregister() method, unregisters with the kernel,
 * receives the object,
 * returns nothing
 */
static int dazuko_unregister(lua_State *L) {
	struct dazuko_object *self;
	int rc;

	dbg(("dazuko.unregister()\n"))

	self = luaL_checkudata(L, 1, METATABLE_NAME);
	luaL_argcheck(L, self != NULL, 1, "'dazuko' object expected");

	if (self->acc != NULL) {
		fprintf(stderr, "BEWARE! unregister() called with an access held\n");
		dbg(("calling dazukoReturnAccess_TS(%p, &%p)", self->id, self->acc))
		rc = dazukoReturnAccess_TS(self->id, &self->acc);
		dbg((" => rc %d, acc %p\n", rc, self->acc))
	}
	if (self->id != NULL) {
		dbg(("calling dazukoUnregister_TS(&%p)", self->id))
		rc = dazukoUnregister_TS(&self->id);
		dbg((" => rc %d, id %p\n", rc, self->id))
	}
	self->ro = 0;

	return(0);
}

/*
 * __gc() meta method, run when the object gets garbage collected,
 * receives the object,
 * returns nothing
 */
static int dazuko_gc(lua_State *L) {
	struct dazuko_object *self;

	dbg(("dazuko.__gc()\n"))

	self = luaL_checkudata(L, 1, METATABLE_NAME);
	if (self != NULL) {
		if (self->acc != NULL) {
			fprintf(stderr, "BEWARE! object GC'ed with an access held\n");
			dbg(("returning pending access\n"))
			dazukoReturnAccess_TS(self->id, &self->acc);
		}
		if (self->id != NULL) {
			fprintf(stderr, "BEWARE! object GC'ed while still registered\n");
			dbg(("unregistering\n"))
			dazukoUnregister_TS(&self->id);
		}
	}

	return(0);
}

/*
 * __tostring() meta method, converts the object to a text representation,
 * receives the object,
 * returns a string
 */
static int dazuko_tostring(lua_State *L) {
	struct dazuko_object *self;

	dbg(("dazuko.__tostring()\n"))

	self = luaL_checkudata(L, 1, METATABLE_NAME);
	luaL_argcheck(L, self != NULL, 1, "'dazuko' object expected");

	lua_pushfstring(L, "dazuko(%p%s%s%s)"
			, self
			, (self->id != NULL) ? ", reg" : ""
			, ((self->id != NULL) && (self->ro)) ? "(ro)" : ""
			, (self->acc != NULL) ? ", acc" : ""
			);

	return(1);
}

/*
 * the Lua interpreter seems to terminate the program upon reception of signals,
 * which breaks out of the getaccess() routine the software usually blocks in
 * (which is OK) but in addition prevents unregister() from getting called --
 * so we swallow signals to not disturb the program's flow (i.e. signals still
 * interrupt getaccess() but allow the application to cleanly unregister() and
 * cleanup before exiting)
 */
static void sighandler(const int sig) {
	/* EMPTY */
	signal(sig, sighandler);
}

static int dazuko_swallowsig(lua_State *L) {
	signal(SIGHUP , sighandler);
	signal(SIGINT , sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGQUIT, sighandler);

	return(0);
}

/*
 * mapping of Lua names to C routines, module functions
 */
static const luaL_reg dazuko_func[] = {
	{ "new", dazuko_new, },
	{ "ioversion", dazuko_ioversion, },
	{ "swallowsig", dazuko_swallowsig, },
	{ NULL, NULL, }
};

/*
 * mapping of Lua names to C routines, object methods
 */
static const luaL_reg dazuko_meth[] = {
	{ "version", dazuko_version, },
	{ "ioversion", dazuko_ioversion, },
	{ "setaccessmask", dazuko_setaccessmask, },
	{ "addincludepath", dazuko_addincludepath, },
	{ "addexcludepath", dazuko_addexcludepath, },
	{ "removeallpaths", dazuko_removeallpaths, },
	{ "getaccess", dazuko_getaccess, },
	{ "unregister", dazuko_unregister, },
	{ "__tostring", dazuko_tostring, },
	{ "__gc", dazuko_gc, },
	{ NULL, NULL, }
};

/*
 * library initialization
 */
LUALIB_API int luaopen_dazuko(lua_State *L) {

	dbg(("initializing " MODULE_NAME " library\n"))

	/* create the "dazuko object" meta table */
	luaL_newmetatable(L, METATABLE_NAME);
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	luaL_register(L, NULL, dazuko_meth);

	/* register module functions and constants */
	luaL_register(L, MODULE_NAME, dazuko_func);
#define ADD_CONST(name) do { \
	lua_pushinteger(L, DAZUKO_ ## name); \
	lua_setfield(L, -2, #name); \
} while (0)
	ADD_CONST(ON_OPEN);
	ADD_CONST(ON_CLOSE);
	ADD_CONST(ON_EXEC);
	ADD_CONST(ON_CLOSE_MODIFIED);
	ADD_CONST(ON_UNLINK);
	ADD_CONST(ON_RMDIR);
#undef ADD_CONST

	/* done, return module's table */
	return(1);
}

#undef MODULE_NAME
#undef METATABLE_NAME

/* ----- E O F ----------------------------------------------- */
