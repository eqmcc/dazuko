/* Java Dazuko Interface. Interace with Dazuko for file access control.
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

/** This class contains a bunch of functions 
 * allowing to pass access control structure 
 * (<code>DazukoAccess</code>) to or read it from Dazuko. 
 *  
 * @see org.dazuko.DazukoAccess
 * @author Alexander Ellwein <alexander.ellwein@avira.com>
 * @author John Ogness <dazukocode@ogness.net>
 * @version tested with Dazuko 2.0.0
 *
 */
public final class Dazuko
{
	public Dazuko()
	{
		super();
		System.loadLibrary("dazuko_jni");
	}

	/** Registers the handler with specified name.
	 * @return 0 if registration was successful.
	 */	
	public final int register(String groupName, String mode)
	{
		try
		{
			return NATIVEregister(groupName, mode);
		}
		catch (Throwable t) { }

		return -1;
	}

	private native int NATIVEregister(String groupName, String mode);
	
	/** Unregisters the handler.
	 */
	public final int unregister()
	{
		try
		{
			return NATIVEunregister();
		}
		catch (Throwable t) { }

		return -1;
	}

	private native int NATIVEunregister();
	
	/** Sets the access mask.
	 * @return 0 if the access mask was set successfully.
	 */
	public final int setAccessMask(int accessMask)
	{
		try
		{
			return NATIVEsetAccessMask(accessMask);
		}
		catch (Throwable t) { }

		return -1;
	}

	private native int NATIVEsetAccessMask(int accessMask);
	
	/** Adds a path that should be included by Dazuko.
	 * @return 0 if the path was added successfully.
	 */
	public final int addIncludePath(String path)
	{
		try
		{
			return NATIVEaddIncludePath(path);
		}
		catch (Throwable t) { }

		return -1;
	}

	private native int NATIVEaddIncludePath(String path);
	
	/** Adds a path that should be excluded by Dazuko.
	 * @return 0 if the path was added successfully. 
	 */
	public final int addExcludePath(String path)
	{
		try
		{
			return NATIVEaddExcludePath(path);
		}
		catch (Throwable t) { }

		return -1;
	}

	private native int NATIVEaddExcludePath(String path);
	
	/** Removes all paths from the path's list.
	 * @return 0 if the paths were removed successfully.
	 */
	public final int removeAllPaths()
	{
		try
		{
			return NATIVEremoveAllPaths();
		}
		catch (Throwable t) { }

		return -1;
	}

	private native int NATIVEremoveAllPaths();

	/** Gets an access to Dazuko interface using DazukoAccess class
	 * container.<br>
	 * <b>IMPORTANT:</b> latency time between <code>getAccess</code> and
	 * <code>returnAccess</code> should be SMALL !
	 * <br>
	 * @param access Access container.
	 * @return DazukoAccess modified container.
	 */
	public final DazukoAccess getAccess()
	{
		try
		{
			return NATIVEgetAccess();
		}
		catch (Throwable t) { }

		return null;
	}

	private native DazukoAccess NATIVEgetAccess();
	
	/** Returns an access container to Dazuko.<br>
	 * <b>IMPORTANT:</b> latency time between <code>getAccess</code>
	 *  and <code>returnAccess</code> should be SMALL !<br>
	 * @param access Access container.
	 * @return boolean 0 if access container was accepted by Dazuko.
	 */
	public final int returnAccess(DazukoAccess access)
	{
		try
		{
			return NATIVEreturnAccess(access);
		}
		catch (Throwable t) { }

		return -1;
	}

	private native int NATIVEreturnAccess(DazukoAccess access);
}
