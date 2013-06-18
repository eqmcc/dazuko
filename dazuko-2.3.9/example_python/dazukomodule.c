/* ----- dazukomodule.c -------------------------------------- */
/* a Python binding for Dazuko */

/*
 * Copyright (c) 2004, 2005 Gerhard Sittig
 * All rights reserved.
 *
 * contributions by Stefan Grundmann (OO style, use of _TS() routines)
 * 
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

#include <Python.h>

#include <dazukoio.h>

static char RcsRevision[] = "$Revision: 1.3 $";

typedef struct {
	PyObject_HEAD
	dazuko_id_t *id;
	struct dazuko_access *acc;
} DazukoObject;

static PyTypeObject Dazuko_Type;
static PyObject *DazukoError = NULL;

static PyObject *
dazuko_ctor(PyTypeObject *type, PyObject *args, PyObject *kwds) {
	DazukoObject *self;
	const char *group, *mode;
	int rc;
	dazuko_id_t *tmp_id;

	mode = "r";
	if (! PyArg_ParseTuple(args, "s|s:register", &group, &mode))
		return NULL;

	tmp_id = NULL;
	rc = dazukoRegister_TS(&tmp_id, group, mode);
	if (rc != 0) {
		PyErr_SetString(DazukoError, "Register() failed");
		return(NULL);
	}

	self = (DazukoObject *)type->tp_alloc(type, 0);
	if (self == NULL) {
		dazukoUnregister_TS(&tmp_id);
		return(NULL);
	}

	self->id = tmp_id;
	self->acc = NULL;
	return((PyObject *)self);
}

static void
dazuko_dtor(DazukoObject *self) {
	if (self->acc != NULL)
		dazukoReturnAccess_TS(self->id, &(self->acc));
	if (self->id != NULL)
		dazukoUnregister_TS(&(self->id));
}

static PyObject *
dazuko_setAccessMask(DazukoObject *self, PyObject *args) {
	unsigned long mask;
	int rc;

	if (! PyArg_ParseTuple(args, "i:setAccessMask", &mask))
		return(NULL);

	rc = dazukoSetAccessMask_TS(self->id, mask);
	if (rc != 0) {
		PyErr_SetString(DazukoError, "SetAccessMask() failed");
		return(NULL);
	}
	Py_INCREF(Py_None);
	return(Py_None);
}

static PyObject *
dazuko_addIncludePath(DazukoObject *self, PyObject *args) {
	const char *path;
	int rc;

	if (! PyArg_ParseTuple(args, "s:addIncludePath", &path))
		return(NULL);

	rc = dazukoAddIncludePath_TS(self->id, path);
	if (rc != 0) {
		PyErr_SetString(DazukoError, "AddIncludePath() failed");
		return(NULL);
	}
	Py_INCREF(Py_None);
	return(Py_None);
}

static PyObject *
dazuko_addExcludePath(DazukoObject *self, PyObject *args) {
	const char *path;
	int rc;

	if (! PyArg_ParseTuple(args, "s:addExcludePath", &path))
		return(NULL);

	rc = dazukoAddExcludePath_TS(self->id, path);
	if (rc != 0) {
		PyErr_SetString(DazukoError, "AddExcludePath() failed");
		return(NULL);
	}
	Py_INCREF(Py_None);
	return(Py_None);
}

static PyObject *
dazuko_removeAllPaths(DazukoObject *self, PyObject *args) {
	int rc;

	if (! PyArg_ParseTuple(args, ""))
		return(NULL);

	rc = dazukoRemoveAllPaths_TS(self->id);
	if (rc != 0) {
		PyErr_SetString(DazukoError, "RemoveAllPaths() failed");
		return(NULL);
	}
	Py_INCREF(Py_None);
	return(Py_None);
}

static PyObject *
dazuko_getAccess(DazukoObject *self, PyObject *args) {
	int rc;
	PyObject *deny;
	PyObject *event, *flags, *mode, *uid, *pid;
	PyObject *filename, *file_size, *file_uid;
	PyObject *file_gid, *file_mode, *file_device;
	PyObject *result;

#define PREP_PARAM(name, format) do { \
	if (self->acc->set_ ##name) { \
		name = Py_BuildValue(format, self->acc-> name); \
	} else { \
		Py_INCREF(Py_None); \
		name = Py_None; \
	} \
} while (0)

	/* no input parameters */
	if (! PyArg_ParseTuple(args, ""))
		return(NULL);

	/* sanity check */
	if (self->acc != NULL) {
		PyErr_SetString(DazukoError, "DANGER! unreturned previous access");
		return(NULL);
	}

	/* get an access (might block longer, allow threads) */
	Py_BEGIN_ALLOW_THREADS
	rc = dazukoGetAccess_TS(self->id, &(self->acc));
	Py_END_ALLOW_THREADS

	/* shortcuts for the error cases */
	if (rc != 0) {
		PyErr_SetString(DazukoError, "GetAccess() failed (nonzero return code)");
		return(NULL);
	}
	if (self->acc == NULL) {
		PyErr_SetString(DazukoError, "GetAccess() failed (NULL access reference)");
		return(NULL);
	}
	if (! self->acc->set_event) {
		dazukoReturnAccess_TS(self->id, &(self->acc));
		PyErr_SetString(DazukoError, "GetAccess() failed (no access event code)");
		return(NULL);
	}

	/*
	 * setup the access parameters to get returned: create
	 * single objects, put them together into a dictionary
	 * and release the references since the dictionary will
	 * reference them from now on
	 */
	deny = Py_BuildValue("i", self->acc->deny);
	PREP_PARAM(event, "i");
	PREP_PARAM(flags, "i");
	PREP_PARAM(mode, "i");
	PREP_PARAM(uid, "i");
	PREP_PARAM(pid, "i");
	PREP_PARAM(filename, "s");
	PREP_PARAM(file_size, "l");
	PREP_PARAM(file_uid, "i");
	PREP_PARAM(file_gid, "i");
	PREP_PARAM(file_mode, "i");
	PREP_PARAM(file_device, "i");
	result = Py_BuildValue("{sOsOsOsOsOsOsOsOsOsOsOsO}"
		, "deny", deny, "event", event
		, "flags", flags, "mode", mode, "uid", uid, "pid", pid
		, "filename", filename, "file_size", file_size
		, "file_uid", file_uid, "file_gid", file_gid
		, "file_mode", file_mode, "file_device", file_device
		);
	Py_XDECREF(deny);
	Py_XDECREF(event);
	Py_XDECREF(flags);
	Py_XDECREF(mode);
	Py_XDECREF(uid);
	Py_XDECREF(pid);
	Py_XDECREF(filename);
	Py_XDECREF(file_size);
	Py_XDECREF(file_uid);
	Py_XDECREF(file_gid);
	Py_XDECREF(file_mode);
	Py_XDECREF(file_device);

	return(result);
}

static PyObject *
dazuko_returnAccess(DazukoObject *self, PyObject *args) {
	int deny;
	int rc;

	deny = 0;
	if (! PyArg_ParseTuple(args, "|i:returnAccess", &deny))
		return(NULL);
	if (self->acc == NULL) {
		PyErr_SetString(DazukoError, "ReturnAccess() failed (no access to return)");
		return(NULL);
	}

	self->acc->deny = (deny != 0) ? 1 : 0;
	rc = dazukoReturnAccess_TS(self->id, &(self->acc));
	if (rc != 0) {
		PyErr_SetString(DazukoError, "ReturnAccess() failed");
		return(NULL);
	}
	Py_INCREF(Py_None);
	return(Py_None);
}

static PyObject *
dazuko_unregister(DazukoObject *self, PyObject *args) {
	int rc;

	if (! PyArg_ParseTuple(args, ""))
		return(NULL);

	if (self->id != NULL)
		rc = dazukoUnregister_TS(&(self->id));
	else
		rc = 0;
	if (rc != 0) {
		PyErr_SetString(DazukoError, "Unregister() failed");
		return(NULL);
	}
	Py_INCREF(Py_None);
	return(Py_None);
}

enum getverstype {
	GET_VERS_KERNEL,
	GET_VERS_IOLIB,
};

static PyObject *
dazuko_getversion(PyObject *self, PyObject *args, const enum getverstype type) {
	struct dazuko_version ver;
	int (*func)(struct dazuko_version *);
	PyObject *txt, *maj, *min, *rev, *rel;
	PyObject *result;

	if (! PyArg_ParseTuple(args, ""))
		return(NULL);

	switch (type) {
	case GET_VERS_KERNEL: func = dazukoVersion; break;
	case GET_VERS_IOLIB: func = dazukoIOVersion; break;
	default: func = NULL; break;
	}
	if (func == NULL) {
		Py_INCREF(Py_None);
		return(Py_None);
	}
	memset(&ver, 0, sizeof(ver));
	if (func(&ver) != 0) {
		Py_INCREF(Py_None);
		return(Py_None);
	}

	txt = Py_BuildValue("s", ver.text);
	maj = Py_BuildValue("i", ver.major);
	min = Py_BuildValue("i", ver.minor);
	rev = Py_BuildValue("i", ver.revision);
	rel = Py_BuildValue("i", ver.release);
	result = Py_BuildValue("{sOsOsOsOsO}"
		, "text", txt
		, "major", maj, "minor", min, "revision", rev, "release", rel
		);
	Py_XDECREF(txt);
	Py_XDECREF(maj);
	Py_XDECREF(min);
	Py_XDECREF(rev);
	Py_XDECREF(rel);

	return(result);
}

static PyObject *
dazuko_version(PyObject *self, PyObject *args) {
	return(dazuko_getversion(self, args, GET_VERS_KERNEL));
}

static PyObject *
dazuko_ioversion(PyObject *self, PyObject *args) {
	return(dazuko_getversion(self, args, GET_VERS_IOLIB));
}

/* module doc string */
PyDoc_STRVAR(DazukoDoc,
	"Dazuko is a means to hook into a machine's file system and can be used\n"
	"to monitor (log for diagnostic purposes) or intercept (filter based on\n"
	"scan results) access to data (files and directories).  Dazuko is mostly\n"
	"used by antivirus scanners to achieve on access scan capabilites.\n"
	"\n"
	"See http://www.dazuko.org/ for additional information.\n"
	"\n"
	"The \"dazuko\" module provides an OO style interface to Dazuko.  Roughly\n"
	"usage is like this:\n"
	"\n"
	"d = dazuko.Dazuko(\"group\", \"rw\")\n"
	"d.setAccessMask(dazuko.ON_OPEN | dazuko.ON_CLOSE)\n"
	"d.addIncludePath(\"/home\")\n"
	"d.addExcludePath(\"/home/excl\")\n"
	"while running:\n"
	"	acc = d.getAccess()\n"
	"	print acc['event'], acc['filename']\n"
	"	deny = check(acc)\n"
	"	d.returnAccess(deny)\n"
	"d.unregister()\n"
	"d = None\n"
	"\n"
	"NOTE: Make sure to spend as little time as necessary when holding an\n"
	"access -- the kernel is waiting for you!  The kernel expects you to\n"
	"handle (ask for and return) accesses as long as you are registered.\n"
	"Not accepting this responsibility may risk the machine's stability."
);

/* module methods */
static PyMethodDef DazukoMethods[] = {
    { "version",  dazuko_version, METH_VARARGS,
	"version()\n"
	"\n"
	"Return the version information for the kernel space part."
    },
    { "ioversion",  dazuko_ioversion, METH_VARARGS,
	"ioversion()\n"
	"\n"
	"Return the version information for the user space part."
    },
    { NULL, NULL, 0, NULL, },
};

/* class doc string */
PyDoc_STRVAR(dazuko_doc,
	"Dazuko(groupname)\n"
	"Dazuko(groupname, regmode)\n"
	"\n"
	"Registers the application with dazuko.\n"
	"regmode can be \"rw\" or \"r\" (optional, \"r\" is the default)."
);

/* class methods */
static PyMethodDef dazuko_methods[] = {
    { "setAccessMask",  (PyCFunction)dazuko_setAccessMask, METH_VARARGS,
	"setAccessMask(3)\n"
	"setAccessMask(dazuko.ON_ACCESS | dazuko.ON_CLOSE)\n"
	"\n"
	"Sets the access mask. Constants are available."
    },
    { "addIncludePath",  (PyCFunction)dazuko_addIncludePath, METH_VARARGS,
	"addIncludePath(pathspec)\n"
	"\n"
	"Adds an include path.  Path specs must be absolute."
    },
    { "addExcludePath",  (PyCFunction)dazuko_addExcludePath, METH_VARARGS,
	"addExcludePath(pathspec)\n"
	"\n"
	"Adds an exclude path.  Path specs must be absolute."
    },
    { "removeAllPaths",  (PyCFunction)dazuko_removeAllPaths, METH_VARARGS,
	"removeAllPaths()\n"
	"\n"
	"Removes all previously set include and exclude paths."
    },
    { "getAccess",  (PyCFunction)dazuko_getAccess, METH_VARARGS,
	"acc = getAccess()\n"
	"\n"
	"Waits for an access, returns the parameters of the access.\n"
	"Accesses gotten MUST be returned to the kernel.  Make sure\n"
	"to spend as little time as necessary while holding the access,\n"
	"the kernel is waiting for you!"
    },
    { "returnAccess",  (PyCFunction)dazuko_returnAccess, METH_VARARGS,
	"returnAccess()\n"
	"returnAccess(do_deny)\n"
	"\n"
	"Return an access gotten from getAccess().  Have the kernel\n"
	"deny the operation to the original caller should do_deny\n"
	"have a nonzero value (optional, allow by default)."
    },
    { "unregister",  (PyCFunction)dazuko_unregister, METH_VARARGS,
	"unregister()\n"
	"\n"
	"Unregister with dazuko."
    },
    { NULL, NULL, 0, NULL, },
};

/* class declaration */
static PyTypeObject Dazuko_Type = {
	PyObject_HEAD_INIT(NULL)
	0,                              /*ob_size*/
	"dazuko.Dazuko",                /*tp_name*/
	sizeof(DazukoObject),           /*tp_basicsize*/
	0,                              /*tp_itemsize*/
	/* methods */
	(destructor)dazuko_dtor,        /*tp_dealloc*/
	0,                              /*tp_print*/
	0,                              /*tp_getattr*/
	0,                              /*tp_setattr*/
	0,                              /*tp_compare*/
	0,                              /*tp_repr*/
	0,                              /*tp_as_number*/
	0,                              /*tp_as_sequence*/
	0,                              /*tp_as_mapping*/
	0,                              /*tp_hash*/
	0,                              /*tp_call*/
	0,                              /*tp_str*/
	PyObject_GenericGetAttr,        /*tp_getattro*/
	0,                              /*tp_setattro*/
	0,                              /*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,       /*tp_flags*/
	dazuko_doc,                     /*tp_doc*/
	0,                              /*tp_traverse*/
	0,                              /*tp_clear*/
	0,                              /*tp_richcompare*/
	0,                              /*tp_weaklistoffset*/
	0,                              /*tp_iter*/
	0,                              /*tp_iternext*/
	dazuko_methods,                 /*tp_methods*/
	0,                              /*tp_members*/
	0,                              /*tp_getset*/
	0,                              /*tp_base*/
	0,                              /*tp_dict*/
	0,                              /*tp_descr_get*/
	0,                              /*tp_descr_set*/
	0,                              /*tp_dictoffset*/
	0,                              /*tp_init*/
	0,                              /*tp_alloc*/
	dazuko_ctor,                    /*tp_new*/
	PyObject_Del,                   /*tp_free*/
	0,                              /*tp_is_gc*/
};

#ifndef PyMODINIT_FUNC
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC
initdazuko(void) {
	PyObject *m;
	char *rev, *sep;
	char ver[10];

	/* set up the module */
	m = Py_InitModule("dazuko", DazukoMethods);

	/* add an inline doc */
	PyModule_AddStringConstant(m, "__doc__", DazukoDoc);

	/* create the exception instance */
	DazukoError = PyErr_NewException("dazuko.error", NULL, NULL);
	Py_INCREF(DazukoError);
	PyModule_AddObject(m, "error", DazukoError);

	/* create the Dazuko class */
	if (PyType_Ready(&Dazuko_Type) < 0)
		return;
	Py_INCREF(&Dazuko_Type);
	PyModule_AddObject(m, "Dazuko", (PyObject *)&Dazuko_Type);

	/* make our revision accessible */
	rev = RcsRevision;
	rev += 11;
	sep = strchr(rev, ' ');
	if (sep != NULL)
		*sep = '\0';
	PyModule_AddStringConstant(m, "VERSION", rev);
	PyModule_AddStringConstant(m, "MODULE_REVISION", rev);
	memset(ver, 0, sizeof(ver));
	snprintf(ver, sizeof(ver), "%d.%d", MAJOR_VERSION, MINOR_VERSION);
	PyModule_AddStringConstant(m, "MODULE_VERSION", ver);

#define ADD_CONST(name) \
	PyModule_AddIntConstant(m, #name , DAZUKO_ ##name)

	/* add the access mask constants */
	ADD_CONST(ON_OPEN);
	ADD_CONST(ON_CLOSE);
	ADD_CONST(ON_EXEC);
	ADD_CONST(ON_CLOSE_MODIFIED);
	ADD_CONST(ON_UNLINK);
	ADD_CONST(ON_RMDIR);
}

/* ----- E O F ----------------------------------------------- */
