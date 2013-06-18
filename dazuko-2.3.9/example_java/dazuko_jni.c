/* JNI Dazuko Interface Wrapper. Interace with Dazuko for file access control.
   Written by Alexander Ellwein <alexander.ellwein@avira.com>

Copyright (c) 2003, 2004, H+BEDV Datentechnik GmbH
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

#include <signal.h>				
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include "dazukoio.h"

#include <jni.h>
#include "org_dazuko_Dazuko.h"

jint JNICALL Java_org_dazuko_Dazuko_NATIVEregister(JNIEnv* env, jobject o, jstring s, jstring m)
{
	int ret;
	const char* str = (*env)->GetStringUTFChars(env, s, 0);
	const char* mod = (*env)->GetStringUTFChars(env, m, 0);

#ifdef _WRAPPER_DEBUG_
	printf("wrapper: register with Dazuko as \"%s\", \"%s\"\n", str, mod); 
#endif

	ret = dazukoRegister(str, mod);
  	
	(*env)->ReleaseStringUTFChars(env, s, str);
	(*env)->ReleaseStringUTFChars(env, m, mod);

	return ret;
}

jint JNICALL Java_org_dazuko_Dazuko_NATIVEunregister(JNIEnv* env, jobject o)
{
#ifdef _WRAPPER_DEBUG_
	printf("wrapper: unregistering from Dazuko\n");
#endif

	return dazukoUnregister();
}

jint JNICALL Java_org_dazuko_Dazuko_NATIVEsetAccessMask(JNIEnv* env, jobject o, jint mask)
{
#ifdef _WRAPPER_DEBUG_
	printf("wrapper: setting access mask\n");
#endif

	return dazukoSetAccessMask(mask);
}

jint JNICALL Java_org_dazuko_Dazuko_NATIVEaddIncludePath(JNIEnv* env, jobject o, jstring s)
{
	int ret;
	const char* str = (*env)->GetStringUTFChars(env, s, 0);

#ifdef _WRAPPER_DEBUG_
      printf("wrapper: adding include path: \"%s\"\n", str);
#endif

	ret = dazukoAddIncludePath(str);

	(*env)->ReleaseStringUTFChars(env, s, str);

	return ret;
}

jint JNICALL Java_org_dazuko_Dazuko_NATIVEaddExcludePath(JNIEnv* env, jobject o, jstring s)
{
	int ret;
	const char* str = (*env)->GetStringUTFChars(env, s, 0);

#ifdef _WRAPPER_DEBUG_
   	printf("wrapper: adding exclude path: \"%s\"\n", str);	
#endif

	ret = dazukoAddExcludePath(str);

	(*env)->ReleaseStringUTFChars(env, s, str);

	return ret;
}

jint JNICALL Java_org_dazuko_Dazuko_NATIVEremoveAllPaths(JNIEnv* env, jobject o)
{
#ifdef _WRAPPER_DEBUG_
	printf("removing all paths\n");
#endif

	return dazukoRemoveAllPaths();
}

jobject JNICALL Java_org_dazuko_Dazuko_NATIVEgetAccess(JNIEnv* env, jobject o)
{
	int ret;
	struct dazuko_access *acc;
	jclass cls;
	jfieldID fid;
	jstring jstr;
	jobject result;

/* define a macro for copying from C to Java */
#define COPYFIELD(name, type, func, src) \
	if (acc->set_##name) \
	{ \
		fid = (*env)->GetFieldID(env, cls, #name, type); \
		if (fid == NULL) \
			goto getAccess_error; \
		(*env)->func(env, result, fid, src); \
		fid = (*env)->GetFieldID(env, cls, "set_" #name, "Z"); \
		if (fid == NULL) \
			goto getAccess_error; \
		(*env)->SetBooleanField(env, result, fid, 1); \
	}
/* end of macro definition */

	ret = dazukoGetAccess(&acc);

	if (ret != 0)
		return NULL;

#ifdef _WRAPPER_DEBUG_
  	printf("wrapper: got access to file from dazuko \n");
#endif
	  
	/* Now we need to move all structure data to Java class */
		
	cls = (*env)->FindClass(env, "org/dazuko/DazukoAccess");				/* getting class type from java */
	if (cls == NULL)
		goto getAccess_error;

	result = (*env)->AllocObject(env, cls); /* allocate same object type as access object */

	COPYFIELD(event, "I", SetIntField, acc->event);
	COPYFIELD(flags, "I", SetIntField, acc->flags);
	COPYFIELD(mode, "I", SetIntField, acc->mode);
	COPYFIELD(uid, "I", SetIntField, acc->uid);
	COPYFIELD(pid, "I", SetIntField, acc->pid);
	jstr = (*env)->NewStringUTF(env, acc->filename);
	if (jstr != NULL)
		COPYFIELD(filename, "Ljava/lang/String;", SetObjectField, jstr);
	COPYFIELD(file_size, "J", SetLongField, acc->file_size);
	COPYFIELD(file_uid, "I", SetIntField, acc->file_uid);
	COPYFIELD(file_gid, "I", SetIntField, acc->file_gid);
	COPYFIELD(file_mode, "I", SetIntField, acc->file_mode);
	COPYFIELD(file_device, "I", SetIntField, acc->file_device);

	fid = (*env)->GetFieldID(env, cls, "c_dazuko_access", "J");
	if (fid == NULL)
		goto getAccess_error;
	(*env)->SetLongField(env, result, fid, (int)acc);

	/* for now, all of the access object member values are filled. */
	return result;	/* return access object */

getAccess_error:

	dazukoReturnAccess(&acc);

	/* something goes wrong, return null reference */
#ifdef _WRAPPER_DEBUG_
	printf("wrapper: failed to get access from dazuko\n");
#endif

	return NULL;
}

jint JNICALL Java_org_dazuko_Dazuko_NATIVEreturnAccess(JNIEnv* env, jobject o, jobject access)
{
	struct dazuko_access *acc;
	jclass cls;
	jfieldID fid;
	long l;
	
#ifdef _WRAPPER_DEBUG_
	printf("wrapper: returning access\n");
#endif

	/* so we need to get data back from Java object into our access structure */
	cls = (*env)->GetObjectClass(env, access);					/* get class type info */
	if (cls == NULL)
		return -1;
        
	fid = (*env)->GetFieldID(env, cls, "c_dazuko_access", "J");
        if (fid == NULL)
		return -1;
        l = (*env)->GetLongField(env, access, fid);
        acc = (struct dazuko_access *)l;

	if (acc == NULL)
		return -1;
        
	fid = (*env)->GetFieldID(env, cls, "deny", "Z");
        if (fid == NULL)
		return -1;
        acc->deny = (*env)->GetBooleanField(env, access, fid);

	return dazukoReturnAccess(&acc);
}
