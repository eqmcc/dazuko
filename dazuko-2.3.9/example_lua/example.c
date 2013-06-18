/* ----- example.c ------------------------------------------- */

/*
 * dazuko enabled C application which embeds Lua to
 * get configuration and access handler from a script
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

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <dazukoio.h>

static int done = 0;
static int verbose = 0;

static void sighandler(const int sig) {
	switch (sig) {
	case SIGINT : done++; break;
	case SIGHUP : done++; break;
	case SIGTERM: done++; break;
	case SIGQUIT: done++; break;
	default: /* EMPTY */; break;
	}
	signal(sig, sighandler);
}

static const luaL_reg dazuko[] = {
	{ NULL, NULL, },
};

static void addconst(lua_State *L) {
	luaL_openlib(L, "dazuko", dazuko, 0);

#define ADD_CONST(c) do { \
	lua_pushinteger(L, DAZUKO_ ## c); \
	lua_setfield(L, -2, #c); \
} while (0)
	ADD_CONST(ON_OPEN);
	ADD_CONST(ON_CLOSE);
	ADD_CONST(ON_EXEC);
	ADD_CONST(ON_CLOSE_MODIFIED);
	ADD_CONST(ON_UNLINK);
	ADD_CONST(ON_RMDIR);

	lua_pop(L, 1); /* the library / namespace */
}

static int loadscript(lua_State *L, const char *filename) {
	if (luaL_loadfile(L, filename) != 0) {
		fprintf(stderr, "error loading script: %s\n", lua_tostring(L, -1));
		return(-1);
	}
	if (lua_pcall(L, 0, 0, 0) != 0) {
		fprintf(stderr, "error running script: %s\n", lua_tostring(L, -1));
		return(-1);
	}
	return(0);
}

static int dazukoloop(lua_State *L, const char *config) {
	dazuko_id_t *id;
	struct dazuko_access *acc;
	int bOK;
	int rc;
	const char *group;
	const char *mode;
	int mask;
	int idx;
	const char *path;
	int funcidx;

	id = NULL;
	acc = NULL;
	bOK = 1;

	/* get the whole bundle */
	lua_getglobal(L, config);
	if (! lua_istable(L, -1)) {
		fprintf(stderr, "config variable \"%s\" not found or not a table\n", config);
		return(-1);
	}
	if (verbose)
		fprintf(stderr, "using configuration \"%s\"\n", config);

	/* get the "group" config item */
	lua_pushliteral(L, "group");
	lua_gettable(L, -2);
	if (! lua_isstring(L, -1)) {
		fprintf(stderr, "group not a string\n");
		bOK = 0;
	}
	group = lua_tostring(L, -1);
	lua_pop(L, 1);
	if (verbose)
		fprintf(stderr, "group is \"%s\"\n", group);

	/* get the "mode" config item */
	lua_pushliteral(L, "mode");
	lua_gettable(L, -2);
	if (! lua_isstring(L, -1)) {
		fprintf(stderr, "mode not a string\n");
		bOK = 0;
	}
	mode = lua_tostring(L, -1);
	lua_pop(L, 1);
	if (verbose)
		fprintf(stderr, "mode is \"%s\"\n", mode);

	if (bOK) {
		rc = dazukoRegister_TS(&id, group, mode);
		if (rc != 0) {
			fprintf(stderr, "could NOT register with Dazuko\n");
			bOK = 0;
		}
	}

	/* get the "mask" config item */
	lua_pushliteral(L, "mask");
	lua_gettable(L, -2);
	if (! lua_isnumber(L, -1)) {
		fprintf(stderr, "mask not a number\n");
		bOK = 0;
	}
	mask = lua_tonumber(L, -1);
	lua_pop(L, 1);
	if (verbose)
		fprintf(stderr, "mask is %d\n", mask);

	if (bOK) {
		rc = dazukoSetAccessMask_TS(id, mask);
		if (rc != 0) {
			fprintf(stderr, "could NOT set the access mask\n");
			bOK = 0;
		}
	}

	/* get the "includes" config item */
	lua_pushliteral(L, "includes");
	lua_gettable(L, -2);
	if (! lua_istable(L, -1)) {
		fprintf(stderr, "includes not a table\n");
		bOK = 0;
	}
	for (idx = 1; bOK; idx++) {
		lua_pushnumber(L, idx);
		lua_gettable(L, -2);
		if (lua_isnil(L, -1)) {
			lua_pop(L, 1);
			break;
		}
		if (! lua_isstring(L, -1)) {
			fprintf(stderr, "include[%d] not a string\n", idx);
			lua_pop(L, 1);
			bOK = 0;
			break;
		}
		path = lua_tostring(L, -1);
		if (verbose)
			fprintf(stderr, "include[%d] is \"%s\"\n", idx, path);

		if (bOK) {
			rc = dazukoAddIncludePath_TS(id, path);
			if (rc != 0) {
				fprintf(stderr, "could NOT add the include path\n");
				bOK = 0;
			}
		}

		lua_pop(L, 1);
	}
	lua_pop(L, 1);

	/* get the "excludes" config item */
	lua_pushliteral(L, "excludes");
	lua_gettable(L, -2);
	if (! lua_istable(L, -1)) {
		fprintf(stderr, "excludes not a table\n");
		bOK = 0;
	}
	for (idx = 1; bOK; idx++) {
		lua_pushnumber(L, idx);
		lua_gettable(L, -2);
		if (lua_isnil(L, -1)) {
			lua_pop(L, 1);
			break;
		}
		if (! lua_isstring(L, -1)) {
			fprintf(stderr, "exclude[%d] not a string\n", idx);
			lua_pop(L, 1);
			bOK = 0;
			break;
		}
		path = lua_tostring(L, -1);
		if (verbose)
			fprintf(stderr, "exclude[%d] is \"%s\"\n", idx, path);

		if (bOK) {
			rc = dazukoAddExcludePath_TS(id, path);
			if (rc != 0) {
				fprintf(stderr, "could NOT add the exclude path\n");
				bOK = 0;
			}
		}

		lua_pop(L, 1);
	}
	lua_pop(L, 1);

	/* get the "handler" config item */
	lua_pushliteral(L, "handler");
	lua_gettable(L, -2);
	if (! lua_isfunction(L, -1)) {
		fprintf(stderr, "handler not a function\n");
		bOK = 0;
	}
	funcidx = lua_gettop(L);
	/* DON'T pop the handler */

	/* loop, wait for access, call handler, return access */
	while ((bOK) && (! done)) {
		rc = dazukoGetAccess_TS(id, &acc);
		if (rc != 0) {
			fprintf(stderr, "ERROR getting access\n");
			bOK = 0;
			continue;
		} else if (acc == NULL) {
			fprintf(stderr, "could NOT get access\n");
			bOK = 0;
			continue;
		} else if (acc->event == 0) {
			fprintf(stderr, "got access with NO event\n");
			bOK = 0;
			rc = dazukoReturnAccess_TS(id, &acc);
			continue;
		}
		if (verbose)
			fprintf(stderr, "got access, calling handler\n");

		lua_pushvalue(L, funcidx);

#define IF_SET(key) \
	if (acc->set_ ##key)
#define ADD_DETAIL_I(key) do { \
	lua_pushliteral(L, #key); \
	lua_pushnumber(L, acc->key); \
	lua_settable(L, -3); \
} while(0)
#define ADD_DETAIL_S(key) do { \
	lua_pushliteral(L, #key); \
	lua_pushstring(L, acc->key); \
	lua_settable(L, -3); \
} while(0)
		lua_newtable(L);
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

		/* XXX support "extra parameters"?  I don't think so */
		rc = lua_pcall(L, 1, 1, 0);

		/* determine deny state */
		if (rc != 0) {
			const char *err;
			err = lua_tostring(L, -1);
			fprintf(stderr, "error in access handler [%s], will grant access\n", err);
			acc->deny = 0;
		} else if (lua_isnil(L, -1)) {
			acc->deny = 0;
		} else if (lua_isboolean(L, -1)) {
			int b;
			b = lua_toboolean(L, -1);
			acc->deny = (b) ? 1 : 0;
		} else if (lua_isnumber(L, -1)) {
			int n;
			n = lua_tonumber(L, -1);
			acc->deny = (n != 0) ? 1 : 0;
		} else {
			fprintf(stderr, "unknown return type from access handler (%d), will grant access\n", lua_type(L, -1));
			acc->deny = 0;
		}

		lua_pop(L, 1); /* take handler's return off the stack */

		if (verbose)
			fprintf(stderr, "access handled, deny is %d\n", acc->deny);

		/* return access to kernel */
		rc = dazukoReturnAccess_TS(id, &acc);
	}

	if (id != NULL) {
		rc = dazukoRemoveAllPaths_TS(id);
	}

	if (id != NULL) {
		rc = dazukoUnregister_TS(&id);
	}

	lua_pop(L, 1); /* handler */
	lua_pop(L, 1); /* config */

	return(0);
}

int main(int argc, char *argv[]) {
	const char *file, *cfg;
	lua_State *L;
	int rc;

	if (argc < 3) {
		fprintf(stderr, "need a script file and a config name\n");
		return(1);
	}
	file = argv[1];
	cfg = argv[2];

	signal(SIGINT , sighandler);
	signal(SIGHUP , sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGQUIT, sighandler);

	L = luaL_newstate();
	luaL_openlibs(L);

	addconst(L);
	if (loadscript(L, file) != 0) {
		return(1);
	}
	rc = dazukoloop(L, cfg);

	lua_close(L);

	return(rc);
}

/* ----- E O F ----------------------------------------------- */
