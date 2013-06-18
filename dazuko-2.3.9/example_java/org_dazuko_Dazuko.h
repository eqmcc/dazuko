/* JNI Dazuko Interface Wrapper Header.
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

#include <jni.h>
/* Header for class org_dazuko_Dazuko */

#ifndef _Included_org_dazuko_Dazuko
#define _Included_org_dazuko_Dazuko
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     org_dazuko_Dazuko
 * Method:    NATIVEregister
 * Signature: (Ljava/lang/String;, Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_dazuko_Dazuko_NATIVEregister
 (JNIEnv *, jobject, jstring, jstring);

/*
 * Class:     org_dazuko_Dazuko
 * Method:    NATIVEunregister
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_dazuko_Dazuko_NATIVEunregister
 (JNIEnv *, jobject);

/*
 * Class:     org_dazuko_Dazuko
 * Method:    NATIVEsetAccessMask
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_org_dazuko_Dazuko_NATIVEsetAccessMask
 (JNIEnv *, jobject, jint);

/*
 * Class:     org_dazuko_Dazuko
 * Method:    NATIVEaddIncludePath
 * Signature: (Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_dazuko_Dazuko_NATIVEaddIncludePath
 (JNIEnv *, jobject, jstring);

/*
 * Class:     org_dazuko_Dazuko
 * Method:    NATIVEaddExcludePath
 * Signature: (Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_org_dazuko_Dazuko_NATIVEaddExcludePath
 (JNIEnv *, jobject, jstring);

/*
 * Class:     org_dazuko_Dazuko
 * Method:    NATIVEremoveAllPaths
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_dazuko_Dazuko_NATIVEremoveAllPaths
 (JNIEnv *, jobject);

/*
 * Class:     org_dazuko_Dazuko
 * Method:    NATIVEgetAccess
 * Signature: ()Lorg/dazuko/DazukoAccess;
 */
JNIEXPORT jobject JNICALL Java_org_dazuko_Dazuko_NATIVEgetAccess
 (JNIEnv *, jobject);

/*
 * Class:     org_dazuko_Dazuko
 * Method:    NATIVEreturnAccess
 * Signature: (Lorg/dazuko/DazukoAccess;)I
 */
JNIEXPORT jint JNICALL Java_org_dazuko_Dazuko_NATIVEreturnAccess
 (JNIEnv *, jobject, jobject);

#ifdef __cplusplus
}
#endif
#endif
