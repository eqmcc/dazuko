/* Java Dazuko Access. Access structure for Dazuko file access control.
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

package org.dazuko;

/** This container class can be passed to Dazuko  
 * in order to control access on files accessed
 * by other applications.
 * 
 * @author Alexander Ellwein <alexander.ellwein@avira.com>
 * @author John Ogness <dazukocode@ogness.net>
 * @version tested with Dazuko 2.0.0
 *
 */
public final class DazukoAccess
{
	public boolean deny = false;
	public int event = 0;
	public boolean set_event = false;
	public int flags = 0;
	public boolean set_flags = false;
	public int mode = 0;
	public boolean set_mode = false;
	public int uid = 0;
	public boolean set_uid = false;
	public int pid = 0;
	public boolean set_pid = false;
	public String filename = null;
	public boolean set_filename = false;
	public long file_size = 0;
	public boolean set_file_size = false;
	public int file_uid = 0;
	public boolean set_file_uid = false;
	public int file_gid = 0;
	public boolean set_file_gid = false;
	public int file_mode = 0;
	public boolean set_file_mode = false;
	public int file_device = 0;
	public boolean set_file_device = false;
	
	public final static int DAZUKO_ON_OPEN = 1;
	public final static int DAZUKO_ON_CLOSE = 2;
	public final static int DAZUKO_ON_EXEC = 4;
	public final static int DAZUKO_ON_CLOSE_MODIFIED = 8;
	public final static int DAZUKO_ON_UNLINK = 16;
	public final static int DAZUKO_ON_RMDIR = 32;

	private long c_dazuko_access = 0;
	
	public DazukoAccess() { }
}
