#!/usr/bin/env python
# ----- example.py ----------------------------------------------

"""Dazuko demonstration script

Dazuko is a means to hook into a machine's file system and can be used
to monitor (log for diagnostic purposes) or intercept (filter based on
scan results) access to data (files and directories).  Dazuko is mostly
used by antivirus scanners to achieve on access scan capabilites.

See http://www.dazuko.org/ for additional information.

The example.py script demonstrates how to use the dazuko module.  It
prints out all open and close access operations performed in the
directory specified on the command line.

Synopsis: [python] example.py directory

"""

__license__ = """

Copyright (c) 2004 Gerhard Sittig
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

"""

__version__ = "0.2"

import sys
import signal
import dazuko

def sigint_handler(*args):
	"""catches CTRL-C"""
	running = 0

def dump(acc):
	"""dump out access data"""

	s = "access"
	if acc['event']:
		s += ", event "
		if acc['event'] == dazuko.ON_OPEN:
			s += "OPEN"
		elif acc['event'] == dazuko.ON_CLOSE:
			s += "CLOSE"
		elif acc['event'] == dazuko.ON_CLOSE_MODIFIED:
			s += "CLOSE_MODIFIED"
		elif acc['event'] == dazuko.ON_EXEC:
			s += "EXEC"
		elif acc['event'] == dazuko.ON_UNLINK:
			s += "UNLINK"
		elif acc['event'] == dazuko.ON_RMDIR:
			s += "RMDIR"
		else:
			s += `acc['event']`
	if acc['flags']:
		s += ", flags " + `acc['flags']`
	if acc['mode']:
		s += ", mode " + `acc['mode']`
	if acc['uid']:
		s += ", uid " + `acc['uid']`
	if acc['pid']:
		s += ", pid " + `acc['pid']`
	if acc['filename']:
		s += ", filename " + acc['filename']
	if acc['file_size']:
		s += ", fsize " + `acc['file_size']`
	if acc['file_uid']:
		s += ", fuid " + `acc['file_uid']`
	if acc['file_gid']:
		s += ", fgid " + `acc['file_gid']`
	if acc['file_mode']:
		s += ", fmode " + `acc['file_mode']`
	if acc['file_device']:
		s += ", device " + `acc['file_device']`
	print s

def test(dir):
	"""the actual test sequence: registers with Dazuko, sets
	the access mask to open and close events, adds the passed
	in path spec (the first command line parameter) as include
	path, excludes /proc, loops to get multiple file accesses
	and print them out, unregisters with Dazuko on shutdown"""

	signal.signal(signal.SIGINT, sigint_handler)
	ver = dazuko.ioversion()
	print "IO version '" + ver['text'] + "'"
	d = dazuko.Dazuko("group", "rw")
	ver = dazuko.version()
	print "module version '" + ver['text'] + "'"
	d.setAccessMask(dazuko.ON_OPEN | dazuko.ON_CLOSE)
	d.addIncludePath(dir)
	d.addExcludePath("/dev/")
	d.addExcludePath("/proc/")
	running = 1
	while running:
		try:
			acc = d.getAccess()
			dump(acc)
			d.returnAccess()
			acc = None
		except:
			running = 0
	d.unregister()
	d = None

if __name__ == "__main__":
	if sys.argv[1:]:
		dir = sys.argv[1]
	else:
		dir = "/tmp"
	test(dir)

# ----- E O F ---------------------------------------------------
