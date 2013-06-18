/* Example Java program demonstrating the capabilities/interface of Dazuko.
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

import org.dazuko.*;

/** This program is a simple application demonstrating how to interface
 *  with Dazuko. The program instructs Dazuko to detect all types of
 *  accesses within the specified directories (or any subdirectory
 *  thereof). The program than prints out the accesses and instructs
 *  Dazuko to allow access.
 *
 *  This program will run only after Dazuko has been successfully installed.
 *  Please see the Dazuko website for information on how to do this.
 *  http://www.dazuko.org
 *
 *  Note: For security reasons, Dazuko will only interact with applications
 *        running as root. Therefore, this example program must also be run
 *        as root.
 * 
 * @author Alexander Ellwein <alexander.ellwein@avira.com>
 * @author John Ogness <dazukocode@ogness.net>
 * @version tested with Dazuko 2.0.0
 *
 */
public class Example
{
	public static void printUsage()
	{
		System.out.println("usage: java Example <dir> <dir> ...");
	}

	public static void printAccess(DazukoAccess acc)
	{
		/* print access data */

		if (!acc.set_event)
			return;

		switch (acc.event)
		{
			case DazukoAccess.DAZUKO_ON_OPEN:
				System.out.print("OPEN   ");
				break;
			case DazukoAccess.DAZUKO_ON_CLOSE:
				System.out.print("CLOSE  ");
				break;
			case DazukoAccess.DAZUKO_ON_CLOSE_MODIFIED:
				System.out.print("CLOSE (modified) ");
				break;
			case DazukoAccess.DAZUKO_ON_EXEC:
				System.out.print("EXEC   ");
				break;
			case DazukoAccess.DAZUKO_ON_UNLINK:
				System.out.print("UNLINK ");
				break;
			case DazukoAccess.DAZUKO_ON_RMDIR:
				System.out.print("RMDIR  ");
				break;
			default:
				System.out.print("????   event:" + acc.event + " ");
				break;
		}

		if (acc.set_uid)
			System.out.print("uid:" + acc.uid + " ");

		if (acc.set_pid)
			System.out.print("pid:" + acc.pid + " ");

		if (acc.set_mode)
			System.out.print("mode:" + acc.mode + " ");

		if (acc.set_flags)
			System.out.print("flags:" + acc.flags + " ");

		if (acc.set_file_uid)
			System.out.print("file_uid:" + acc.file_uid + " ");

		if (acc.set_file_gid)
			System.out.print("file_gid:" + acc.file_gid + " ");

		if (acc.set_file_mode)
			System.out.print("file_mode:" + acc.file_mode + " ");

		if (acc.set_file_device)
			System.out.print("file_device:" + acc.file_device + " ");

		if (acc.set_file_size)
			System.out.print("file_size:" + acc.file_size + " ");

		if (acc.set_filename)
			System.out.print("filename:" + acc.filename + " ");

		System.out.println("");
	}

	/** programm entry point 
	 * 
	 * @param args parameters - directories for Dazuko to watch
	 */
	public static void main(String[] args)
	{
		Dazuko dazuko = new Dazuko();
		boolean RUNNING = true;
		DazukoAccess acc;
		boolean args_ok = false;
		int i;
		
		if (dazuko.register("DAZUKO_EXAMPLE_JAVA", "r+") != 0)
		{
			System.out.println("error: failed to register with Dazuko");
			System.exit(-1);
		}

		System.out.println("registered with Dazuko successfully");

		if (dazuko.setAccessMask(DazukoAccess.DAZUKO_ON_OPEN | DazukoAccess.DAZUKO_ON_CLOSE | DazukoAccess.DAZUKO_ON_CLOSE_MODIFIED | DazukoAccess.DAZUKO_ON_EXEC | DazukoAccess.DAZUKO_ON_UNLINK | DazukoAccess.DAZUKO_ON_RMDIR) != 0)
		{
			System.out.println("error: failed to set access mask");
			dazuko.unregister();
			System.exit(-1);
		}

		System.out.println("set access mask successfully");

		/* set scan path */
		for (i=0 ; i<args.length ; i++)
		{
			if (args[i].charAt(0) == '/')
			{
				if (dazuko.addIncludePath(args[i]) != 0)
				{
					System.out.println("error: failed to add " + args[i] + " include path");
					dazuko.unregister();
					System.exit(-1);
				}

				args_ok = true;
			}
		}

		/* ignore /dev/ */
		if (dazuko.addExcludePath("/dev/") != 0)
		{
			System.out.println("error: failed to add /dev/ exclude path");
			dazuko.unregister();
			System.exit(-1);
		}

		if (!args_ok)
		{
			printUsage();
			dazuko.unregister();
			System.exit(-1);
		}

		System.out.println("set scan path successfully");

		while (RUNNING)
		{
			/* get an access */
			acc = dazuko.getAccess();

			if (acc != null)
			{
				printAccess(acc);

				/* always allow access */
				acc.deny = false;

				/* return access (IMPORTANT, the kernel is waiting for us!) */
				if (dazuko.returnAccess(acc) != 0)
				{
					System.out.println("error: failed to return access");
					RUNNING = false;
				}
			}
			else
			{
				System.out.println("warning: failed to get an access");
				RUNNING = false;
			}
		}

		/* unregister with Dazuko */
		if (dazuko.unregister() != 0)
		{
			System.out.println("error: failed to unregister with Dazuko");
			System.exit(-1);
		}

		System.out.println("unregistered with Dazuko successfully");
	}
}
