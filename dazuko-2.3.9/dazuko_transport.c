/* Dazuko Transport. Types shared between userspace and kernelspace.
   Written by Gerhard Sittig <gsittig@antivir.de>

   Copyright (c) 2005 H+BEDV Datentechnik GmbH
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

/*
 * representation of "struct dazuko_request" in a form which is unambigious
 * across several platforms or between subsystems within a single platform
 *
 * high level language data types may vary in their size or internal
 * representation on the machine code level, high level language constructions
 * like a "struct" in C "suffer" from the compiler's freedom to align or
 * rearrange its fields
 *
 * since it is essential for Dazuko's functioning that the application and the
 * kernel agree in how to interpret the dazuko_request layout, we introduce an
 * intermediate format for passing this struct around
 *
 * this allows for 32bit applications to keep working against a 64bit kernel,
 * or to operate a Linux binary in a FreeBSD emulation, or to compile kernel
 * module and application with different options, or whatever influences the
 * layout of the high level language struct -- we don't mind any longer
 *
 * layout of the structure:
 * - no high level data type but a pure byte array
 * - fixed width header fields describing the sizeof an integer, a character and
 *   a pointer respectively, plus the stream's total length and a "used" flag
 * - variable width values following with the size specified before and thus known
 */

#if defined __KERNEL__ || defined _KERNEL
  /* kernel part, every system has its own includes for NULL and int32_t :( */

  #if defined LINUX || defined LINUX26_SUPPORT
    #include <linux/stddef.h>
    #include <linux/types.h>
  #elif defined __FreeBSD__
	#if defined FREEBSD7_SUPPORT
		#include <sys/stddef.h>
	#elif defined FREEBSD8_SUPPORT
		#include <sys/stddef.h>
	#else
    		#include <stdio.h>
	#endif
    	#include <sys/types.h>
  #elif defined __sun__
    #include <stdio.h>
    #include <sys/types.h>
  #endif

#else /* __KERNEL__ */
  /* user land part (regular app), not much nicer than kernel space */

  /* for NULL */
  #include <stdio.h>

  /* we have to get int32_t from somewhere */
  #include <sys/types.h>
  #ifndef __BIT_TYPES_DEFINED__
    #if defined __sun__ || defined __OpenBSD__ || defined __FreeBSD__
      #include <inttypes.h>
    #else
      #include <stdint.h>
    #endif
  #endif

#endif /* __KERNEL__ */

#include "dazuko_transport.h"

/*
 * we need an integer to hold (store and transport) pointers; XXX what is a
 * reliable way to detect the width of pointers?  the warning here is to inform
 * us at compile time -- is there some #info directive which is not as
 * "serious" as a compiler warning?
 *
 * we actually could do without introducing this extra type and always use
 * int64_t which merely would issue a compiler warning (but would still work)
 * in all the cases where pointers are not of 64bit width
 */

/* define this if you want to see the outcome of the decision */
#undef WANT_INT_PTR_NOTIFICATION

#if defined(_LP64) || defined(_I32LPx)
	#if defined WANT_INT_PTR_NOTIFICATION
	#warning using 64bit integer to store pointers
	#endif
	#define int_ptr_t	int64_t
#else
	#if defined WANT_INT_PTR_NOTIFICATION
	#warning using 32bit integer to store pointers
	#endif
	#define int_ptr_t	int32_t
#endif

/* ----- base routines ----- */

/* get a byte from a position within the buffer
 * and increment the buffer pointer */
static int getbyte(unsigned char **p, int *b)
{
	if (p == NULL)
		return -1;

	if (*p == NULL)
		return -1;

	if (b == NULL)
		return -1;

	*b = **p;
	(*p)++;

	return 0;
}

/* get an integer from a position within the buffer with the specified width
 * and increment the buffer pointer */
static int getinteger(unsigned char **p, int *b, int count)
{
	int	res;
	int	idx;

	if (p == NULL)
		return -1;

	if (*p == NULL)
		return -1;

	if (b == NULL)
		return -1;

	res = 0;
	for (idx=0 ; idx<count ; idx++)
	{
		res <<= 8;
		res += **p;
		(*p)++;
	}
	*b = res;

	return 0;
}

int dazuko_reqstream_chunksize(unsigned char *ll, int *size)
{
	/* this is a wrapper to getinteger that does NOT
	 * increment the buffer pointer */

	unsigned char *p = ll;

	return getinteger(&p, size, 4);
}

/* get a pointer from a position within the buffer with the specified width
 * and increment the buffer pointer */
static int getpointer(unsigned char **p, char **b, int count)
{
	int_ptr_t	res;
	int		idx;

	if (p == NULL)
		return -1;

	if (*p == NULL)
		return -1;

	if (b == NULL)
		return -1;

	res = 0;
	for (idx = 0; idx<count ; idx++)
	{
		res <<= 8;
		res += **p;
		(*p)++;
	}

	*b = (void *)res;

	return 0;
}

/* put a byte to a position within the buffer
 * and increment the buffer pointer */
static int putbyte(unsigned char **p, int b)
{
	if (p == NULL)
		return -1;

	if (*p == NULL)
		return -1;

	**p = b;
	(*p)++;

	return 0;
}

/* put an integer to a position within the buffer with the specified width
 * and increment the buffer pointer */
static int putinteger(unsigned char **p, int b, int count)
{
	int	val;
	int	idx;

	if (p == NULL)
		return -1;

	if (*p == NULL)
		return -1;

	val = b;
	for (idx=1 ; idx<=count ; idx++)
	{
		*(*p + count - idx) = (val & 0xFF);
		val >>= 8;
	}
	*p += count;

	return 0;
}

/* put a pointer to a position within the buffer with the specified width
 * and increment the buffer pointer */
static int putpointer(unsigned char **p, char *b, int count)
{
	int_ptr_t	val;
	int		 idx;

	if (p == NULL)
		return -1;

	if (*p == NULL)
		return -1;

	val = (int_ptr_t)b;
	for (idx=1 ; idx<=count ; idx++)
	{
		*(*p + count - idx) = (val & 0xFF);
		val >>= 8;
	}
	*p += count;

	return(0);
}

/* skip over data */

static int skipinteger(unsigned char **p, int count)
{
	if (p == NULL)
		return -1;

	if (*p == NULL)
		return -1;

	(*p) += count;

	return 0;
}

static int skippointer(unsigned char **p, int count)
{
	if (p == NULL)
		return -1;

	if (*p == NULL)
		return -1;

	(*p) += count;

	return(0);
}

/* ----- public routines ----- */

/* get the size of a low level byte stream representation */
int dazuko_reqstream_dim_chunk0(int size_chr, int size_int, int size_ptr)
{
	/*
	 * a request consists of:
	 * chunk0 length (as 4-byte integer)
	 * used flag, sizeof char/int/void* (as single bytes)
	 * type, in size, out size, out used (as integers)
	 * in buff, out buff (as pointers)
	 */
	return (4 + (4 * size_chr) + (4 * size_int) + (2 * size_ptr));
}

/*
 * convert a high level struct into a low level stream
 * (this is the app handing its variable over to the kernel)
 */
int dazuko_reqstream_hl2ll(struct dazuko_request *req, unsigned char *ll)
{
	unsigned char	*wrptr;
	int		size_chr;
	int		size_int;
	int		size_ptr;
	int		size_req;
	int		type_as_int;

	wrptr = ll;

	/* prepare to write */
	size_chr = sizeof(char);
	size_int = sizeof(int);
	size_ptr = sizeof(void *);
	size_req = dazuko_reqstream_dim_chunk0(size_chr, size_int, size_ptr);

	/*
	 * we do not support multi byte characters
	 * and we assume maximum int and ptr sizes
	 */
	/*
	 * XXX how to check these at compile time?
	 * #if (sizeof int < 4)
	 * etc did not work :(
	 */
	if (size_chr != 1)
		return -1;

	/* convert everything to base types */
	type_as_int = (req->type[0] << 8) + (req->type[1] << 0);

	/* stream out */
	if (putinteger(&wrptr, size_req, 4) != 0) return -1;
	if (putbyte(&wrptr, 0) != 0) return -1;
	if (putbyte(&wrptr, size_chr) != 0) return -1;
	if (putbyte(&wrptr, size_int) != 0) return -1;
	if (putbyte(&wrptr, size_ptr) != 0) return -1;
	if (putinteger(&wrptr, type_as_int, size_int) != 0) return -1;
	if (putinteger(&wrptr, req->buffer_size, size_int) != 0) return -1;
	if (putpointer(&wrptr, req->buffer, size_ptr) != 0) return -1;
	if (putinteger(&wrptr, req->reply_buffer_size, size_int) != 0) return -1;
	if (putpointer(&wrptr, req->reply_buffer, size_ptr) != 0) return -1;
	if (putinteger(&wrptr, req->reply_buffer_size_used, size_int) != 0) return -1;

	/* done */
	return 0;
}

/*
 * convert a low level stream into a high level struct
 * (this is the app reading back its variable after the kernel updated it)
 */
int dazuko_reqstream_ll2hl(unsigned char *ll, struct dazuko_request *req, int strict)
{
	unsigned char	*rdptr;
	int		size_req;
	int		req_used;
	int		size_chr;
	int		size_int;
	int		size_ptr;
	int		type_as_int;

	rdptr = (unsigned char *)ll;

	/* only accept streams with our own layout (length part) */
	if (getinteger(&rdptr, &size_req, 4) != 0) return -1;
	if (strict)
	{
		if (size_req != dazuko_reqstream_dim_chunk0(sizeof(char), sizeof(int), sizeof(void *)))
			return -1;
	}

	/* the kernel MUST have updated the stream, otherwise it's invalid */
	if (getbyte(&rdptr, &req_used) != 0) return -1;
	if (strict)
	{
		if (!req_used)
			return -1;
	}

	/* only accept streams with our own layout (type width part) */
	if (getbyte(&rdptr, &size_chr) != 0) return -1;
	if (getbyte(&rdptr, &size_int) != 0) return -1;
	if (getbyte(&rdptr, &size_ptr) != 0) return -1;
	if (strict)
	{
		if ((size_chr != sizeof(char)) || (size_int != sizeof(int)) || (size_ptr != sizeof(void *)))
			return -1;
	}
	if (size_req != dazuko_reqstream_dim_chunk0(size_chr, size_int, size_ptr))
		return -1;

	/* stream in values */
	if (getinteger(&rdptr, &type_as_int, size_int) != 0) return -1;
	if (getinteger(&rdptr, &req->buffer_size, size_int) != 0) return -1;
	if (getpointer(&rdptr, &req->buffer, size_ptr) != 0) return -1;
	if (getinteger(&rdptr, &req->reply_buffer_size, size_int) != 0) return -1;
	if (getpointer(&rdptr, &req->reply_buffer, size_ptr) != 0) return -1;
	if (getinteger(&rdptr, &req->reply_buffer_size_used, size_int) != 0) return -1;

	/* post convert to req */
	req->type[0] = (type_as_int >> 8) & 0xFF;
	req->type[1] = (type_as_int >> 0) & 0xFF;

	/* done */
	return 0;
}

/*
 * update a low level stream with data from a high level struct
 * (this is the kernel passing back data to the app inside the app's variable)
 */
int dazuko_reqstream_updll(struct dazuko_request *req, unsigned char *ll)
{
	unsigned char	*wrptr;
	int		size_chr;
	int		size_int;
	int		size_ptr;
	int		size_req;

	wrptr = ll;

	/* fetch the complete length spec to check it later */
	if (getinteger(&wrptr, &size_req, 4) != 0) return -1;

	/* rather aux a test for minimum length */
	if (size_req < dazuko_reqstream_dim_chunk0(1, 4, 4))
		return -1;

	/* set the "used" flag */
	/*
	 * XXX delay this to a later point in time???  OTOH the update routine
	 * will return an error when later steps fail and the stream will not
	 * get passed back to the application, so this seems OK
	 */
	if (putbyte(&wrptr, 1) != 0) return -1;

	/* fetch the data width fields to check them */
	if (getbyte(&wrptr, &size_chr) != 0) return -1;
	if (getbyte(&wrptr, &size_int) != 0) return -1;
	if (getbyte(&wrptr, &size_ptr) != 0) return -1;
	if (size_chr != 1)
		return -1;
	if (size_req != dazuko_reqstream_dim_chunk0(size_chr, size_int, size_ptr))
		return -1;

	/* skip over the fields not of interest, only write back the
	 * "reply_buffer_size_used" component */
	if (skipinteger(&wrptr, size_int) != 0) return -1;
	if (skipinteger(&wrptr, size_int) != 0) return -1;
	if (skippointer(&wrptr, size_ptr) != 0) return -1;
	if (skipinteger(&wrptr, size_int) != 0) return -1;
	if (skippointer(&wrptr, size_ptr) != 0) return -1;
	if (putinteger(&wrptr, req->reply_buffer_size_used, size_int) != 0) return -1;

	/* done */
	return 0;
}

