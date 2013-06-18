/* ----- Dazuko.c -------------------------------------------- */
/* ruby extension for Dazuko, wrapper around libdazuko.a */

/*
 * Copyright (c) 2004 Gerhard Sittig
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

#include "ruby.h"
#include <dazukoio.h>

/*
 * NOTES and TODO
 *
 * - how to release the data structure with the event details?
 * - improve the embedded documentation markup
 * - catch exceptions when running the get_access() code block?
 */

/* { ----- diagnostics hack ----- */

/*
 * debugging with "ruby -d" works, rb_warning does print text;
 * but "irb -d" or "irb> $DEBUG = true" don't work (ruby bug?);
 * so we "cheat", check for $DEBUG ourselves and use rb_warn()
 */
static int is_debug = 0;

static void check_debug(void) {
	VALUE d;

	d = rb_gv_get("$DEBUG");
	if (d == Qnil)
		return;
	if (TYPE(d) == T_TRUE)
		is_debug = 1;
	else if (TYPE(d) == T_FALSE)
		is_debug = 0;
}

#define rb_warning if (is_debug) rb_warn

/* } ----- diagnostics hack ----- */
/* { ----- helper stuff ----- */

enum access_want {
	WANT_ARRAY,
	WANT_HASH,
};

enum registered_mode {
	REG_NONE,
	REG_READONLY,
	REG_READWRITE,
};

/*
 * store internal data in this struct, bind it to the object instance;
 * don't hold them in instance variables, don't pass them up to callers
 */
typedef struct _dazuko_object_data {
	VALUE self;
	dazuko_id_t *id;
	struct dazuko_access *acc;
	int silent;
	enum access_want acc_want;
	enum registered_mode reg_mode;
} dazuko_object_data;

/*
 * check if we have to release essential resources
 * when the object gets GCed (hints towards app flaws)
 */
static void object_data_free(void *data) {
	dazuko_object_data *p;
	int rc;

	check_debug();

	p = data;
	if (p == NULL)
		return;

	/* ruby frees the Dazuko instance while acc is still set? */
	if (p->acc != NULL) {
		rb_warn("Dazuko class: GC frees instance %p with access %p still held", p->self, p->acc);
		rb_warning("calling dazukoReturnAccess_TS(%p, %p)", p->id, p->acc);
		rc = dazukoReturnAccess_TS(p->id, &(p->acc));
		rb_warning("dazukoReturnAccess_TS() => %d, acc %p", rc, p->acc);
	}

	/* ruby frees the Dazuko instance while id is still set? */
	if (p->id != NULL) {
		rb_warn("Dazuko class: GC frees instance %p which is registered", p->self);
		rb_warning("calling dazukoUnregister_TS(%p)", p->id);
		rc = dazukoUnregister_TS(&(p->id));
		rb_warning("dazukoUnregister_TS() => %d, id %p", rc, p->id);
	}

	free(p);
}

/* } ----- helper stuff ----- */
/* { ----- Dazuko class ----- */

/*
 * call-seq: Dazuko.new()
 * 
 * creates a new instance of the Dazuko class, takes no arguments
 */
static VALUE d_new(VALUE class) {
	dazuko_object_data *p;
	VALUE obj;
	VALUE args[1];

	check_debug();

	rb_warning("d_new(), class = %p", class);

	p = ALLOC(dazuko_object_data);
	obj = Data_Wrap_Struct(class, NULL, object_data_free, p);
	rb_warning("d_new(), got object data memory, C ptr %p, ruby obj %p", p, obj);

	memset(p, 0, sizeof(*p));
	p->self = obj;
	p->id = NULL;
	p->acc = NULL;
	p->silent = 0;
	p->acc_want = WANT_HASH;
	p->reg_mode = REG_NONE;

	args[0] = Qnil;
	rb_obj_call_init(obj, 0, args);

	rb_warning("d_new(), done, self = %p", obj);
	return(obj);
}

/*
 * call-seq: Dazuko#initialize()
 * 
 * presets instance variables,
 * private method (usually called by new() and not by an application)
 */
static VALUE d_initialize(VALUE self) {
	check_debug();

	rb_warning("d_initialize(), self = %p", self);

	rb_iv_set(self, "@group", Qnil);
	rb_iv_set(self, "@mode", Qnil);
	rb_iv_set(self, "@mask", Qnil);
	rb_iv_set(self, "@incl", Qnil);
	rb_iv_set(self, "@excl", Qnil);

	rb_warning("d_initialize(), done");
	return(self);
}

/*
 * call-seq: Dazuko#register(group, mode = "r")
 * 
 * registers the application with the dazuko device
 * 
 * +group+ is a string and traditionally consists of a vendor part
 * and an application part separated by a colon.
 * The optional +mode+ parameter is a string and may be "r" for
 * read only (log) mode or "rw" for read and write (scanner, filter)
 * mode.
 * 
 * Note that in read only mode the application only learns
 * about accesses but cannot block (deny) them.
 * 
 * The method returns +true+ for success, +false+ otherwise.
 */
static VALUE d_register(VALUE self, VALUE args) {
	dazuko_object_data *p;
	VALUE arg;
	char *group, *mode;
	int rc;

	check_debug();

	rb_warning("d_register(), self %p", self);

	/* get a handle to the internal variables */
	Data_Get_Struct(self, dazuko_object_data, p);
	if (p->id != NULL) {
		if (! p->silent)
			rb_warn("Dazuko#register(): instance already registered");
		return(Qfalse);
	}

	/* we get an array with one or two parameters */
	/* use rb_scan_args() for this? */
	Check_Type(args, T_ARRAY);

	arg = rb_ary_entry(args, 0);
	Check_Type(arg, T_STRING);
	group = STR2CSTR(arg);

	arg = rb_ary_entry(args, 1);
	if (arg != Qnil) {
		Check_Type(arg, T_STRING);
		mode = STR2CSTR(arg);
	} else {
		mode = "r";
	}

	/* register with dazuko */
	rb_warning("d_register(), calling dazukoRegister_TS(%p, \"%s\", \"%s\")", p->id, group, mode);
	rc = dazukoRegister_TS(&(p->id), group, mode);
	rb_warning("d_register(), dazukoRegister_TS() => %d, id %p", rc, p->id);
	if (rc != 0) {
		return(Qfalse);
	}

	/* store group and mode, preset configuration to empty values */
	rb_iv_set(self, "@group", rb_str_new2(group));
	rb_iv_set(self, "@mode", rb_str_new2(mode));
	rb_iv_set(self, "@mask", INT2NUM(0));
	rb_iv_set(self, "@incl", rb_ary_new());
	rb_iv_set(self, "@excl", rb_ary_new());

	/* keep track of ro/rw mode (ATM only to warn) */
	/* adjust this when more modes than r/rw/r+ are valid */
	if (strcmp(mode, "r") == 0) {
		p->reg_mode = REG_READONLY;
	} else if ((strcmp(mode, "rw") == 0) || (strcmp(mode, "r+") == 0)) {
		p->reg_mode = REG_READWRITE;
	} else {
		p->reg_mode = REG_NONE;
		rb_warn("Dazuko#register(): unknown \"%s\" mode parameter", mode);
	}

	rb_warning("d_register(), done");
	return(Qtrue);
}

/*
 * call-seq: Dazuko#set_mask(mask)
 * 
 * sets the kind of accesses the application wants to get
 * 
 * The +mask+ parameter should be determined by ORing together
 * the +DAZUKO_ON_OPEN+ etc constants (see the "CONSTANTS" section).
 * 
 * The method returns +true+ for success, +false+ otherwise.
 */
static VALUE d_set_mask(VALUE self, VALUE msk) {
	dazuko_object_data *p;
	int mask;
	int rc;

	check_debug();

	rb_warning("d_set_mask(), self %p", self);

	Data_Get_Struct(self, dazuko_object_data, p);
	if (p->id == NULL) {
		if (! p->silent)
			rb_warn("Dazuko#set_mask(): instance not registered yet");
		return(Qfalse);
	}

	Check_Type(msk, T_FIXNUM);
	mask = NUM2INT(msk);

	rc = dazukoSetAccessMask_TS(p->id, mask);
	rb_warning("d_set_mask(), dazukoSetAccessMask_TS(%p, %d) => %d", p->id, mask, rc);
	if (rc != 0) {
		return(Qfalse);
	}
	rb_iv_set(self, "@mask", INT2NUM(mask));

	rb_warning("d_set_mask(), done");
	return(Qtrue);
}

/*
 * internal routine for the common logic of Dazuko#add_include() and Dazuko#add_exclude()
 */
static VALUE d_inclexcl(VALUE self, VALUE args, int bIsIncl) {
	dazuko_object_data *p;
	VALUE list, item;
	size_t idx;
	char *path;
	int rc;

	rb_warning("d_inclexcl(), self %p", self);

	Data_Get_Struct(self, dazuko_object_data, p);
	if (p->id == NULL) {
		if (! p->silent)
			rb_warn("Dazuko#add_%sclude(): instance not registered yet", bIsIncl ? "in" : "ex");
		return(Qfalse);
	}

	/* determine which list to add to */
	list = rb_iv_get(self, bIsIncl ? "@incl" : "@excl");

	/* we receive an array with the Ruby caller's parameters */
	Check_Type(args, T_ARRAY);

	/* safety belt, if no nil has been at the end now it is */
	rb_ary_push(args, Qnil);

	/* cope with an empty list, that's fine with us */
	item = rb_ary_entry(args, 0);
	if (item == Qnil)
		return(Qtrue);

	/* if the first parameter is an array, it should be the only one */
	if (TYPE(item) == T_ARRAY) {
		if (rb_ary_entry(args, 1) != Qnil)
			return(Qfalse);
		args = item;
		rb_ary_push(args, Qnil);
	}

	/* we expect the arguments to be an array of strings */
	for (idx = 0; /* EMPTY */; idx++) {
		item = rb_ary_entry(args, idx);
		if (item == Qnil)
			break;
		Check_Type(item, T_STRING);
		path = STR2CSTR(item);
		rc = bIsIncl
			? dazukoAddIncludePath_TS(p->id, path)
			: dazukoAddExcludePath_TS(p->id, path)
			;
		rb_warning("d_inclexcl(), dazukoAdd%scludePath_TS(%p, \"%s\") => %d", bIsIncl ? "In" : "Ex", p->id, path, rc);
		if (rc != 0) {
			return(Qfalse);
		}
		rb_ary_push(list, item);
	}

	rb_warning("d_inclexcl(), done");
	return(Qtrue);
}

/*
 * call-seq: Dazuko#add_include(*pathspec)
 * 
 * adds path specifications to the kernel module's include list
 * 
 * The +pathspec+ parameter can be an array of strings (in this case
 * it should be the only parameter) or a sequence of simple strings.
 *
 * For example "([ '/i1', '/i2' ])" or "([ '/i3' ])" or
 * "('/i4', '/i5', '/i6')" or "('/i7')" are acceptable.
 * Even "([])" or "(nil)" or no parameters at all are valid since
 * this may simplify the application's logic.
 * "([ '/i8', '/i9' ], '/i10')" is not and will be rejected
 * (this should not happen in real world applications, anyway).
 *
 * The method returns +true+ for success, +false+ otherwise.
 *
 * Note that you have to pass _absolute_ and _unified_ path specifications
 * to the kernel module's list.  These parameters will not be normalized
 * any further but later accesses will be compared against them.  Relative
 * path specifications are illegal and will make this method fail.
 * Unexpanded specifications (e.g. path names with symlinks or '..' in them)
 * will make you miss access events.
 */
static VALUE d_add_include(VALUE self, VALUE args) {
	VALUE rc;

	check_debug();

	rb_warning("d_add_include(), self %p", self);
	rc = d_inclexcl(self, args, 1);
	rb_warning("d_add_include(), done");

	return(rc);
}

/*
 * call-seq: Dazuko#add_exclude(*pathspec)
 * 
 * adds path specifications to the kernel module's exclude list
 * 
 * See Dazuko#add_include() for details.
 */
static VALUE d_add_exclude(VALUE self, VALUE args) {
	VALUE rc;

	check_debug();

	rb_warning("d_add_exclude(), self %p", self);
	rc = d_inclexcl(self, args, 0);
	rb_warning("d_add_exclude(), done");

	return(rc);
}

/*
 * call-seq: Dazuko#remove_paths()
 * 
 * clears all currently set include and exclude paths
 * 
 * The method returns +true+ for success, +false+ otherwise.
 */
static VALUE d_remove_paths(VALUE self) {
	dazuko_object_data *p;
	int rc;

	check_debug();

	rb_warning("d_remove_paths(), self %p", self);

	Data_Get_Struct(self, dazuko_object_data, p);
	if (p->id == NULL) {
		if (! p->silent)
			rb_warn("Dazuko#remove_paths(): instance not registered yet");
		return(Qfalse);
	}

	rc = dazukoRemoveAllPaths_TS(p->id);
	rb_warning("d_remove_paths(), dazukoRemoveAllPaths_TS(%p) => %d", p->id, rc);
	if (rc != 0) {
		return(Qfalse);
	}

	rb_iv_set(self, "@incl", rb_ary_new());
	rb_iv_set(self, "@excl", rb_ary_new());

	rb_warning("d_remove_paths(), done");
	return(Qtrue);
}

/*
 * call-seq: Dazuko#get_access() { |acc| ... }
 * 
 * waits until a file access according to the configured access mask
 * happens in or under one of the configured include paths but not
 * in or under a configured exclude path
 * 
 * The code block provided by the caller will be run with the access
 * operation's details passed in.  The code block's return value will
 * determine whether the access will be denied (non zero value) or
 * granted (zero value).
 * 
 * For convenience other forms of returning the deny status are
 * accepted, too:  the boolean +true+ and +false+ values, the "yes"
 * and "no" and the "true" and "false" and the "1" and "0" strings
 * are allowed next to numerical return values.
 *
 * In case the access handler fails (terminates abnormally) the access
 * will be denied.  This behaviour is not configurable and was chosen to
 * fail on the safe side.
 * 
 * The access details contain the following items:
 * an up to this moment determined deny state (might have been
 * influenced by other dazuko enabled applications), the type of
 * access event and event specific data: flags of the file operation,
 * permission bits for the file operation, UID and PID of the process
 * carrying out the access, the name, the size, the owning UID and GID,
 * the permission bits of the file which is accessed and the device
 * the file lives on.  Note that not every event will
 * have valid or useful values for every parameter.
 * 
 * The access details are stored in a hash while the key names
 * are the names of the +dazuko_access+ struct fields in the
 * "dazukoio.h" header file:  "deny", "event", "flags", "mode",
 * "uid", "pid", "filename", "file_size", "file_uid", "file_gid",
 * "file_mode", and "file_device".  Alternatively the details
 * can be stored in an array in the above mentioned order.  See
 * the Dazuko#access_want() method on how to request this
 * presentation of the details.
 *
 * The method returns +true+ for success, +false+ otherwise.
 * 
 * _BEWARE_:  Accesses gotten from the kernel in read and write mode _must_
 * be returned to the kernel, and registered applications _must_ call
 * Dazuko#get_access() to handle pending accesses.  Otherwise you may risk
 * your system's stability!  The kernel will suspend any file system access
 * until one registered process will get and handle it.  Note also that
 * the kernel holds the file access while you handle it, so take care to
 * spend as little time as necessary in this situation.
 * 
 * Although the Dazuko extension will catch exceptions thrown from
 * within the access handler and tries to carry out operations the
 * application fails to initiate (will return accesses should the access
 * handler fail, will unregister with the dazuko device when
 * Dazuko#unregister() was not called, etc) you should take care to not
 * cause failure or unnecessary delays in your access handler.  These
 * builtin safety belts may jump in too late should the kernel wait for
 * your application to handle access events, so the system may already
 * be blocked.
 */
static VALUE d_get_access(VALUE self) {
	dazuko_object_data *p;
	int rc;
	VALUE data, deny;
	int prev_deny;

	check_debug();

	rb_warning("d_get_access(), self %p", self);

	Data_Get_Struct(self, dazuko_object_data, p);
	if (p->id == NULL) {
		if (! p->silent)
			rb_warn("Dazuko#get_access(): instance not registered yet");
		return(Qfalse);
	}

	/* uh, now THIS is heavy -- an access has not been returned ... */
	if (p->acc != NULL) {
		rb_warn("Dazuko#get_access(): access %p still held", p->acc);
		rb_warning("d_get_access(), calling dazukoReturnAccess_TS(%p, %p)", p->id, p->acc);
		rc = dazukoReturnAccess_TS(p->id, &(p->acc));
		rb_warning("d_get_access(), dazukoReturnAccess_TS() => %d, acc %p", rc, p->acc);
	}

	/* there's no point in requesting an access without a handler */
	if (! rb_block_given_p()) {
		rb_warn("Dazuko#get_access(): no code block to run for the event");
		return(Qfalse);
	}

	/* wait for the next access to happen */
	p->acc = NULL;
	rb_warning("d_get_access(), calling dazukoGetAccess_TS(%p, %p)", p->id, p->acc);
	rc = dazukoGetAccess_TS(p->id, &(p->acc));
	rb_warning("d_get_access(), dazukoGetAccess_TS() => %d, acc %p", rc, p->acc);
	if (rc != 0) {
		/* no access -> return(false) */
		rb_warning("d_get_access(), error occured");
		return(Qfalse);
	} else if (p->acc == NULL) {
		/* no data -> return(false) */
		rb_warning("d_get_access(), no data");
		return(Qfalse);
	} else if (! p->acc->event) {
		/* no event -> ReturnAccess(), return(false) */
		rb_warning("d_get_access(), no event");
		rb_warning("d_get_access(), calling dazukoReturnAccess_TS(%p, %p)", p->id, p->acc);
		dazukoReturnAccess_TS(p->id, &(p->acc));
		rb_warning("d_get_access(), dazukoReturnAccess_TS() => %d, acc %p", rc, p->acc);
		return(Qfalse);
	}
	rb_warning("d_get_access(), GOT event");

	/* create a data structure from the event details */
	rb_warning("d_get_access(), creating data structure");
	switch (p->acc_want) {
	case WANT_HASH: {
		/* pass a hash, this is a little more expensive but
		 * results in more readable Ruby handler code */
		data = rb_hash_new();
		rb_hash_aset(data, rb_str_new2("deny"), INT2NUM(p->acc->deny));
		if (p->acc->set_event)
			rb_hash_aset(data, rb_str_new2("event"), INT2NUM(p->acc->event));
		if (p->acc->set_flags)
			rb_hash_aset(data, rb_str_new2("flags"), INT2NUM(p->acc->flags));
		if (p->acc->set_mode)
			rb_hash_aset(data, rb_str_new2("mode"), INT2NUM(p->acc->mode));
		if (p->acc->set_uid)
			rb_hash_aset(data, rb_str_new2("uid"), INT2NUM(p->acc->uid));
		if (p->acc->set_pid)
			rb_hash_aset(data, rb_str_new2("pid"), INT2NUM(p->acc->pid));
		if (p->acc->set_filename)
			rb_hash_aset(data, rb_str_new2("filename"), rb_str_new2(p->acc->filename));
		if (p->acc->set_file_size)
			rb_hash_aset(data, rb_str_new2("file_size"), INT2NUM(p->acc->file_size));
		if (p->acc->set_file_uid)
			rb_hash_aset(data, rb_str_new2("file_uid"), INT2NUM(p->acc->file_uid));
		if (p->acc->set_file_gid)
			rb_hash_aset(data, rb_str_new2("file_gid"), INT2NUM(p->acc->file_gid));
		if (p->acc->set_file_mode)
			rb_hash_aset(data, rb_str_new2("file_mode"), INT2NUM(p->acc->file_mode));
		if (p->acc->set_file_device)
			rb_hash_aset(data, rb_str_new2("file_device"), INT2NUM(p->acc->file_device));
		}
		break;
	case WANT_ARRAY: {
		/* pass an array, this is simple but the application
		 * needs to know about the element sequence */
		data = rb_ary_new();
		rb_ary_push(data, INT2NUM(p->acc->deny));
		rb_ary_push(data, p->acc->set_event ? INT2NUM(p->acc->event) : Qnil);
		rb_ary_push(data, p->acc->set_flags ? INT2NUM(p->acc->flags) : Qnil);
		rb_ary_push(data, p->acc->set_mode ? INT2NUM(p->acc->mode) : Qnil);
		rb_ary_push(data, p->acc->set_uid ? INT2NUM(p->acc->uid) : Qnil);
		rb_ary_push(data, p->acc->set_pid ? INT2NUM(p->acc->pid) : Qnil);
		rb_ary_push(data, p->acc->set_filename ? rb_str_new2(p->acc->filename) : Qnil);
		rb_ary_push(data, p->acc->set_file_size ? INT2NUM(p->acc->file_size) : Qnil);
		rb_ary_push(data, p->acc->set_file_uid ? INT2NUM(p->acc->file_uid) : Qnil);
		rb_ary_push(data, p->acc->set_file_gid ? INT2NUM(p->acc->file_gid) : Qnil);
		rb_ary_push(data, p->acc->set_file_mode ? INT2NUM(p->acc->file_mode) : Qnil);
		rb_ary_push(data, p->acc->set_file_device ? INT2NUM(p->acc->file_device) : Qnil);
		}
		break;
	default:
		rb_warn("Dazuko#get_access(): incomplete switch statement, please notify the dazuko vendor");
		data = Qnil;
		break;
	}

	/* call the given code block which returns deny status */
	rb_warning("d_get_access(), calling code block");
	prev_deny = p->acc->deny;
	rc = 0;
	deny = rb_protect(rb_yield, data, &rc);
	if (rc != 0) {
		if (p->silent < 2)
			rb_warn("Dazuko#get_access(): access handler abnormally terminated");
		if (p->reg_mode == REG_READWRITE) {
			if (p->silent < 2)
				rb_warn("Dazuko#get_access(): will deny access");
			deny = Qtrue;
		} else {
			deny = Qfalse; /* silence the below code path */
		}
	}

	/* yes, we are overly tolerant here :) */
	if (deny == Qnil) {
		rb_warning("d_get_access(), block returned nil");
		p->acc->deny = 0;
	} else if (TYPE(deny) == T_FIXNUM) {
		rb_warning("d_get_access(), block returned fixnum(%d)", (int)NUM2INT(deny));
		p->acc->deny = (NUM2INT(deny) != 0) ? 1 : 0;
	} else if (TYPE(deny) == T_TRUE) {
		rb_warning("d_get_access(), block returned true");
		p->acc->deny = 1;
	} else if (TYPE(deny) == T_FALSE) {
		rb_warning("d_get_access(), block returned false");
		p->acc->deny = 0;
	} else if (TYPE(deny) == T_STRING) {
		char *s;
		s = STR2CSTR(deny);
		rb_warning("d_get_access(), block returned string \"%s\"", s);
		if (strcmp(s, "yes") == 0) {
			p->acc->deny = 1;
		} else if (strcmp(s, "true") == 0) {
			p->acc->deny = 1;
		} else if (strcmp(s, "1") == 0) {
			p->acc->deny = 1;
		} else if (strcmp(s, "no") == 0) {
			p->acc->deny = 0;
		} else if (strcmp(s, "false") == 0) {
			p->acc->deny = 0;
		} else if (strcmp(s, "0") == 0) {
			p->acc->deny = 0;
		} else {
			rb_warn("Dazuko#get_access(): unexpected \"%s\" return value from the access handler", s);
		}
	} else {
		rb_warn("Dazuko#get_access(): unexpected return type %d from the access handler", (int)TYPE(deny));
	}
	rb_warning("d_get_access(), deny %d", p->acc->deny);

	/* this kind of error can be hard to find (speaking from experience) */
	if ((p->acc->deny != 0) && (prev_deny == 0) && (p->reg_mode != REG_READWRITE)) {
		rb_warn("Dazuko#get_access(): request to deny access was ignored, not registered for rw mode");
	}

	/* return the event to dazuko */
	rb_warning("d_get_access(), calling dazukoReturnAccess_TS(%p, %p)", p->id, p->acc);
	rc = dazukoReturnAccess_TS(p->id, &(p->acc));
	rb_warning("d_get_access(), dazukoReturnAccess_TS() => %d, acc %p", rc, p->acc);

	/* dispose the event details data structure */
	/* XXX how to? rb_free_generic_ivar()? */
	rb_iv_set(self, "@access", data);
	data = Qnil;
	rb_iv_set(self, "@access", Qnil);

	rb_warning("d_get_access(), done");
	return(Qtrue);
}

/*
 * call-seq: Dazuko#unregister()
 * 
 * unregisters the application with the dazuko device
 * 
 * The method returns +true+ for success, +false+ otherwise.
 */
static VALUE d_unregister(VALUE self) {
	dazuko_object_data *p;
	int rc;

	check_debug();

	rb_warning("d_unregister(), self %p", self);

	Data_Get_Struct(self, dazuko_object_data, p);
	if (p->id == NULL) {
		if (! p->silent)
			rb_warn("Dazuko#unregister(): instance not registered yet");
		return(Qfalse);
	}

	/* uh, now THIS is heavy -- an access has not been returned ... */
	if (p->acc != NULL) {
		rb_warn("Dazuko#unregister(): access %p still held", p->acc);
		rb_warning("d_unregister(), calling dazukoReturnAccess_TS(%p, %p)", p->id, p->acc);
		rc = dazukoReturnAccess_TS(p->id, &(p->acc));
		rb_warning("d_unregister(), dazukoReturnAccess_TS() => %d, acc %p", rc, p->acc);
	}

	rb_warning("d_unregister(), calling dazukoUnregister_TS(%p)", p->id);
	rc = dazukoUnregister_TS(&(p->id));
	rb_warning("d_unregister(), dazukoUnregister_TS() => %d, id %p", rc, p->id);
	if (rc != 0) {
		return(Qfalse);
	}

	/* reset variables now that the dazuko connection has gone */
	/* just call "d_initialize(self);"?  but this might not be
	 * appropriate in the future when more code will be added there */
	rb_iv_set(self, "@group", Qnil);
	rb_iv_set(self, "@mode", Qnil);
	rb_iv_set(self, "@mask", Qnil);
	rb_iv_set(self, "@incl", Qnil);
	rb_iv_set(self, "@excl", Qnil);

	p->reg_mode = REG_NONE;

	rb_warning("d_unregister(), done");
	return(Qtrue);
}

enum getverstype {
	GET_VERS_KERNEL,
	GET_VERS_IOLIB,
};

static VALUE d_version_common(VALUE self, const enum getverstype type) {
	struct dazuko_version ver;
	int (*func)(struct dazuko_version *);
	VALUE res;

	switch (type) {
	case GET_VERS_KERNEL: func = dazukoVersion; break;
	case GET_VERS_IOLIB: func = dazukoIOVersion; break;
	default: return(Qnil);
	}
	memset(&ver, 0, sizeof(ver));
	if (func(&ver) != 0) {
		res = Qnil;
	} else {
		res = rb_hash_new();
		rb_hash_aset(res, rb_str_new2("text"), rb_str_new2(ver.text));
		rb_hash_aset(res, rb_str_new2("major"), INT2NUM(ver.major));
		rb_hash_aset(res, rb_str_new2("minor"), INT2NUM(ver.minor));
		rb_hash_aset(res, rb_str_new2("revision"), INT2NUM(ver.revision));
		rb_hash_aset(res, rb_str_new2("release"), INT2NUM(ver.release));
	}
	return(res);
}

/*
 * call-seq: Dazuko#version?
 *
 * returns the version information of the kernel space part
 */
static VALUE d_version_query(VALUE self) {
	return(d_version_common(self, GET_VERS_KERNEL));
}

/*
 * call-seq: Dazuko#ioversion?
 *
 * returns the version information of the user space part
 */
static VALUE d_ioversion_query(VALUE self) {
	return(d_version_common(self, GET_VERS_IOLIB));
}

/*
 * call-seq: Dazuko#silent?
 *
 * queries the status of (ab)use warnings controlled by Dazuko#silent(),
 * returns +true+ or +false+
 */
static VALUE d_silent_query(VALUE self) {
	dazuko_object_data *p;
	VALUE res;

	check_debug();

	Data_Get_Struct(self, dazuko_object_data, p);
	res = (p->silent != 0) ? Qtrue : Qfalse;

	return(res);
}

/*
 * call-seq: Dazuko#silent(flag)
 * 
 * controls if warnings should be displayed (+true+) or not (+false+)
 * when the application tries to use an instance without (successfully)
 * calling Dazuko#register()
 *
 * The method returns the previous state of the flag
 * or +nil+ in the case of an error.
 */
static VALUE d_silent(VALUE self, VALUE flag) {
	dazuko_object_data *p;
	VALUE res;
	char *s;

	check_debug();

	rb_warning("d_silent(), self %p", self);

	Data_Get_Struct(self, dazuko_object_data, p);
	rb_warning("d_silent(), prev %d", p->silent);
	res = d_silent_query(self);

	if (TYPE(flag) == T_TRUE) {
		p->silent = 1;
	} else if (TYPE(flag) == T_FALSE) {
		p->silent = 0;
	} else if (TYPE(flag) == T_FIXNUM) {
		p->silent = (NUM2INT(flag) != 0) ? 1 : 0;
	} else if (TYPE(flag) == T_STRING) {
		s = STR2CSTR(flag);
		if (strcmp(s, "really_only_for_the_unit_test") == 0)
			p->silent = 2;
		else
			rb_warn("Dazuko#silent(): unknown parameter \"%d\"", s);
	} else {
		rb_warn("Dazuko#silent(): unknown parameter type %d", (int)TYPE(flag));
		return(Qnil);
	}
	rb_warning("d_silent(), now %d", p->silent);

	rb_warning("d_silent(), done");
	return(res);
}

/*
 * call-seq: Dazuko#access_want?
 *
 * queries the presentation of access details controlled
 * by the Dazuko#access_want() method, returns a string
 */
static VALUE d_access_want_query(VALUE self) {
	dazuko_object_data *p;
	VALUE res;

	check_debug();

	Data_Get_Struct(self, dazuko_object_data, p);
	switch (p->acc_want) {
	case WANT_ARRAY:
		res = rb_str_new2("Array");
		break;
	case WANT_HASH:
		res = rb_str_new2("Hash");
		break;
	default:
		rb_warn("Dazuko#access_want?(): incomplete switch statement, please notify the dazuko vendor");
		res = Qnil;
		break;
	}

	return(res);
}

/*
 * call-seq: Dazuko#access_want(how)
 * 
 * controls how the access event details are passed to the handler
 * code block in Dazuko#get_access()
 * 
 * The +how+ parameter can be "Array" or "Hash" to set how the
 * access event details are passed for future accesses.
 * 
 * The method returns the previous state of the setting in a string
 * or +nil+ in case of an error.
 */
static VALUE d_access_want(VALUE self, VALUE flag) {
	dazuko_object_data *p;
	VALUE res;

	check_debug();

	rb_warning("d_access_want(), self %p", self);
	Data_Get_Struct(self, dazuko_object_data, p);

	res = d_access_want_query(self);

	rb_warning("d_access_want(), prev %d", p->acc_want);
	if (flag == Qnil) {
		/* EMPTY */
	} else if (TYPE(flag) == T_STRING) {
		char *s;

		s = STR2CSTR(flag);
		if (strcmp(s, "Array") == 0) {
			p->acc_want = WANT_ARRAY;
		} else if (strcmp(s, "Hash") == 0) {
			p->acc_want = WANT_HASH;
		} else {
			rb_warn("Dazuko#access_want(): unknown parameter \"%s\"", s);
			return(Qnil);
		}
	} else if (TYPE(flag) == T_ARRAY) {
		p->acc_want = WANT_ARRAY;
	} else if (TYPE(flag) == T_HASH) {
		p->acc_want = WANT_HASH;
	} else {
		rb_warn("Dazuko#access_want(): unknown parameter type %d", (int)TYPE(flag));
		return(Qnil);
	}
	rb_warning("d_access_want(), now %d", p->acc_want);

	rb_warning("d_access_want(), done");
	return(res);
}

/*
 * Document-class: Dazuko
 * 
 * == NAME
 * 
 * Dazuko - a ruby extension to interface with the dazuko device
 * 
 * == SYNOPSIS
 * 
 *   require 'Dazuko'
 * 
 *   d = Dazuko.new
 *   d.register("vendor:app", "rw")
 *   d.set_mask(Dazuko::DAZUKO_ON_OPEN | Dazuko::DAZUKO_ON_CLOSE)
 *   d.add_include('/export/home', '/shared')
 *   d.add_exclude('/dev/')
 *   loop do
 *       rc = d.get_access() do |acc|
 *           # handle access, inspect acc['filename'] etc ...
 *           # "return" whether to deny or grant access
 *       end
 *       break if (! rc)
 *   end
 *   d.unregister()
 *   d = nil
 * 
 * == DESCRIPTION
 * 
 * The dazuko device is a means to hook into a machine's file system
 * and can be used to monitor (log for diagnostic purposes) or
 * intercept (filter based on scan results) access to data (files
 * and directories).  The dazuko device is mostly used by antivirus
 * scanners to achieve on access scan capabilites.
 * 
 * The Dazuko extension provides a ruby interface to the dazuko device.
 * The source code of this extension comes with an example of
 * how to interface with dazuko.  The extension is part of the
 * dazuko distribution package.
 * 
 * == METHODS
 * 
 * The Dazuko class provides the following methods:
 * 
 * - Dazuko.new()
 * - Dazuko#register(group, mode)
 * - Dazuko#set_mask(bits)
 * - Dazuko#add_include(directories)
 * - Dazuko#add_exclude(directories)
 * - Dazuko#remove_paths()
 * - Dazuko#get_access() { |acc| ... }
 * - Dazuko#unregister()
 * - Dazuko#silent(flag)
 * - Dazuko#access_want(how)
 * - Dazuko#version?
 * - Dazuko#ioversion?
 * 
 * See the description of the Dazuko#get_access() method, it
 * almost completely summarizes what all this is about.
 *
 * == VARIABLES
 *
 * A Dazuko instance has the following (read only) variables:
 *
 * - @group, @mode:
 *   set to the appropriate parameters after successful registration
 *   with Dazuko#register()
 * - @mask:
 *   set to the appropriate parameter after successfully setting an
 *   access mask with Dazuko#set_mask()
 * - @incl, @excl:
 *   expanded with the appropriate parameters after successfully adding
 *   path specifications with Dazuko#add_include() or Dazuko#add_exclude()
 *
 * == CONSTANTS
 * 
 * The bit mask for the access operations passed to Dazuko#set_mask()
 * can be ORed together with the following predefined values:
 * 
 *   Dazuko::DAZUKO_ON_OPEN
 *   Dazuko::DAZUKO_ON_CLOSE
 *   Dazuko::DAZUKO_ON_EXEC
 *   Dazuko::DAZUKO_ON_CLOSE_MODIFIED
 *   Dazuko::DAZUKO_ON_UNLINK
 *   Dazuko::DAZUKO_ON_RMDIR
 * 
 * == DIAGNOSTICS
 *
 * Progress messages and information on internals are shown when
 * running the interpreter in debug mode.  This illustrates how the
 * Ruby methods are mapped to the C dazukoio library calls.
 *
 *   ruby -d example.rb `pwd`
 *
 * The Dazuko extension additionally issues warnings when it detects
 * flaws in the use of its API (i.e. when it thinks that the
 * application does something unusual or even dangerous).  These
 * messages can be controlled with the Dazuko#silent() method.
 *
 * More serious situations are reported regardless of the "silent" flag,
 * even when running in non debug mode.
 *
 * Since the dazuko device actually expands the kernel's power into the
 * userland, any dazuko enabled application accepts a great responsibility
 * for the system's robustness and stability.  So warnings should be taken
 * very seriously.
 *
 * == AUTHOR
 * 
 * Gerhard Sittig <gsittig@antivir.de>
 * 
 * == SEE ALSO
 * 
 * http://www.dazuko.org/
 * 
 */

static VALUE cDazuko;

void Init_Dazuko(void) {
	check_debug();

	rb_warning("Init_Dazuko()");

	/* create the "Dazuko" class */
	cDazuko = rb_define_class("Dazuko", rb_cObject);

	/* create Dazuko's methods */
	rb_define_singleton_method(cDazuko, "new", d_new, 0);
	rb_define_method(cDazuko, "initialize", d_initialize, 0);
	rb_define_method(cDazuko, "register", d_register, -2);
	rb_define_method(cDazuko, "set_mask", d_set_mask, 1);
	rb_define_method(cDazuko, "add_include", d_add_include, -2);
	rb_define_method(cDazuko, "add_exclude", d_add_exclude, -2);
	rb_define_method(cDazuko, "remove_paths", d_remove_paths, 0);
	rb_define_method(cDazuko, "get_access", d_get_access, 0);
	rb_define_method(cDazuko, "unregister", d_unregister, 0);
	rb_define_method(cDazuko, "silent?", d_silent_query, 0);
	rb_define_method(cDazuko, "silent", d_silent, 1);
	rb_define_method(cDazuko, "access_want?", d_access_want_query, 0);
	rb_define_method(cDazuko, "access_want", d_access_want, 1);
	rb_define_method(cDazuko, "version?", d_version_query, 0);
	rb_define_method(cDazuko, "ioversion?", d_ioversion_query, 0);

	/* make these instance variables available (read only) */
	rb_define_attr(cDazuko, "group", 1, 0);
	rb_define_attr(cDazuko, "mode", 1, 0);
	rb_define_attr(cDazuko, "mask", 1, 0);
	rb_define_attr(cDazuko, "incl", 1, 0);
	rb_define_attr(cDazuko, "excl", 1, 0);

	/* create access mask constants */
#define ADD_CONST(c) rb_define_const(cDazuko, #c, INT2NUM(c))
	ADD_CONST(DAZUKO_ON_OPEN);
	ADD_CONST(DAZUKO_ON_CLOSE);
	ADD_CONST(DAZUKO_ON_EXEC);
	ADD_CONST(DAZUKO_ON_CLOSE_MODIFIED);
	ADD_CONST(DAZUKO_ON_UNLINK);
	ADD_CONST(DAZUKO_ON_RMDIR);

	rb_warning("Init_Dazuko() done, cDazuko %p", cDazuko);
}

/* } ----- Dazuko class ----- */

/* ----- E O F ----------------------------------------------- */
