#!/usr/bin/env ruby

# == SYNOPSIS
# example.rb [options] [include ...]
# 
# == DESCRIPTION
# 
# Dazuko is a means to hook into a machine's file system and can be used
# to monitor (log for diagnostic purposes) or intercept (filter based on
# scan results) access to data (files and directories).  Dazuko is mostly
# used by antivirus scanners to achieve on access scan capabilites.
# 
# The example.rb script demonstrates how to use the Dazuko extension in
# ruby style (in an object oriented manner), with and without threads.
# 
# == OPTIONS
# 
# Any path specification following the options is taken as an include path
# (just like the "--incl" option had been specified).
# 
# === --help
# 
# Print out a help screen
# 
# === --mask number
# 
# Set the access mask to this value.  The numeric parameter
# is determined by adding the appropriate bits for the
# operations as defined in the +DAZUKO_ON_OPEN+ etc constants.
# 
# === --incl path
# 
# Adds the specified path to the list of include paths.
# 
# This option can be specified multiple times.  Multiple arguments
# can be specified when separated with colons.
# 
# === --excl path
# 
# Adds the specified path to the list of exclude paths.
# 
# This option can be specified multiple times.  Multiple arguments
# can be specified when separated with colons.
# 
# === --want type
# 
# This options specifies how event details should be passed to the
# access handler.  Valid types are "Array" and "Hash".
# 
# === --deny
# 
# This option toggles the behaviour of the access handler.  When
# it is active, all files with the pattern "deny" in their path name
# are denied.
# 
# Use this option with care!  See the README and the Perl binding's
# README for details.
# 
# === --thrd number
# 
# Without this option the script runs a single instance of the
# Dazuko class.  When this option is given, this many threads
# with one Dazuko instance for each are started.
# 
# == AUTHOR
# 
# Gerhard Sittig <gsittig@antivir.de>
# 
# == SEE ALSO
# 
# Dazuko(3)
# 
# http://www.dazuko.org/


# ----- license (BSD style) -------------------------------------
# {

$license = <<END_OF_LICENSE

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

END_OF_LICENSE

# }
# ----- the program logic ---------------------------------------
# {

require 'Dazuko'
require 'English'
require 'getoptlong'

$mask = Dazuko::DAZUKO_ON_OPEN | Dazuko::DAZUKO_ON_CLOSE
$incl = []
$excl = [ "/dev/", "/proc/" ]
$want = "Hash"
$deny = false
$thrd = 0

# print out a help message on the script's options
def synopsis()
	print "synopsis: #{ $PROGRAM_NAME } [options] [include ...]\n"
	print "\n"
	print "options:\n"
	print "--help\t\t" "this text\n"
	print "--mask num\t" "set the access mask to value \"num\"\n"
	print "--incl dir\t" "add \"dir\" to the list of includes\n"
	print "--excl dir\t" "add \"dir\" to the list of excludes\n"
	print "--want type\t" "choose the presentation for the access details\n"
	print "--deny\t\t" "deny access to files with \"deny\" in their pathname\n"
	print "--thrd num\t" "start this many threads with Dazuko instances\n"
	print "\n"
	print "every non option argument will be treated as an include path\n"
end

# helper to print out the access details when passed as array
def iter_access_array(acc)
	yield("deny access" , acc[ 0]) if (acc[ 0])
	yield("access type" , acc[ 1]) if (acc[ 1])
	yield("access flags", acc[ 2]) if (acc[ 2])
	yield("access mode" , acc[ 3]) if (acc[ 3])
	yield("access uid"  , acc[ 4]) if (acc[ 4])
	yield("access pid"  , acc[ 5]) if (acc[ 5])
	yield("file name"   , acc[ 6]) if (acc[ 6])
	yield("file size"   , acc[ 7]) if (acc[ 7])
	yield("file uid"    , acc[ 8]) if (acc[ 8])
	yield("file gid"    , acc[ 9]) if (acc[ 9])
	yield("file mode"   , acc[10]) if (acc[10])
	yield("file device" , acc[11]) if (acc[11])
end

# access handler when details are passed as array
def handle_access_array(acc, nr)
	# dump event data
	print "\n"
	print "nr #{ nr } " if (nr != 0)
	print "got an access event (array):\n"
	iter_access_array(acc) do |name, val|
		print "\t#{ name } is #{ val }\n"
	end

	# block access when (enabled and) certain checks apply
	deny_rc = false
	if ($deny) then
		if ((acc[6] != nil) && (acc[6] =~ /deny/)) then
			print "filename matches /deny/\n"
			deny_rc = true
		end
	end

	# work around the lack of data release code in Dazuko.c:
	# free as much of the access data as we can do here
	acc = nil

	# return the deny status
	return(deny_rc)
end

# access handler when details are passed as hash
def handle_access_hash(acc, nr)
	# dump event data
	print "\n"
	print "nr #{ nr } " if (nr != 0)
	print "got an access event (hash):\n"
	acc.each do |name, val|
		print "\t#{ name } => #{ val }\n"
	end

	# block access when (enabled and) certain checks apply
	deny_rc = false
	if ($deny) then
		if ((acc['filename'] != nil) && (acc['filename'] =~ /deny/)) then
			print "filename matches /deny/\n"
			deny_rc = true
		end
	end

	# work around the lack of data release code in Dazuko.c:
	# free as much of the access data as we can do here
	acc = nil

	# return the deny status
	return(deny_rc)
end

# the main logic: setup a Dazuko instance, get accesses
def main(nr)
	print "main(#{ nr })\n" if (nr != 0)

	ok = true

	# preparation
	d = Dazuko.new
	ver = d.ioversion?
	print "IO version #{ ver['text'] }\n"
	ok = false if ((ok) and (! d.register("example:ruby", ($deny) ? "rw" : "r")))
	if (ok) then
		ver = d.version?
		print "module version #{ ver['text'] }\n"
	end
	ok = false if ((ok) and (! d.set_mask($mask)))
	ok = false if ((ok) and (! d.add_include($incl)))
	ok = false if ((ok) and (! d.add_exclude($excl)))
	ok = false if ((ok) and (! d.access_want($want)))

	# get accesses (until error or interrupt)
	trap('INT') do
		ok = false
	end
	loop do
		break if (! ok)
		rc = d.get_access() do |acc|
			deny_rc = false
			if (acc.class == Array) then
				deny_rc = handle_access_array(acc, nr)
			elsif (acc.class == Hash) then
				deny_rc = handle_access_hash(acc, nr)
			else
				print "unknown type of access data \"#{ acc.class }\"\n"
			end
			print "will #{ (deny_rc) ? 'deny' : 'grant' } access\n"
			deny_rc
		end
		break if (! rc)
	end

	# cleanup
	d.unregister() if (d.group != nil)
	d = nil
end

# preparation steps (scan options, check parameters)
def prep()
	# scan cmdline options
	opts = GetoptLong.new(
		[ "--help", "-h", GetoptLong::NO_ARGUMENT ],
		[ "--mask", "-m", GetoptLong::REQUIRED_ARGUMENT ],
		[ "--incl", "-i", GetoptLong::REQUIRED_ARGUMENT ],
		[ "--excl", "-e", GetoptLong::REQUIRED_ARGUMENT ],
		[ "--want", "-w", GetoptLong::REQUIRED_ARGUMENT ],
		[ "--deny", "-d", GetoptLong::NO_ARGUMENT ],
		[ "--thrd", "-t", GetoptLong::REQUIRED_ARGUMENT ]
	)
	opts.each do |opt, arg|
		if (opt == "--help") then
			synopsis()
			exit(0)
		elsif (opt == "--mask") then
			$mask = arg.to_i
		elsif (opt == "--incl") then
			$incl << arg.to_s
		elsif (opt == "--excl") then
			$excl << arg.to_s
		elsif (opt == "--want") then
			$want = arg.to_s
		elsif (opt == "--deny") then
			$deny = ! $deny
		elsif (opt == "--thrd") then
			$thrd = arg.to_i
		else
			synopsis()
			exit(1)
		end
	end

	# remaining arguments are includes
	$ARGV.each do |arg|
		$incl << arg.to_s
	end

	# split arrays (makes "--incl 1:2 --incl 3" work)
	$incl = $incl.join(':').split(':')
	$excl = $excl.join(':').split(':')

	# make all path names absolute / unified
	$incl.map! do |fn|
		File.expand_path(fn)
	end
	$excl.map! do |fn|
		File.expand_path(fn)
	end

	# print out parameters
	print "parameter dump:\n"
	print "\taccess mask #{ $mask }\n"
	print "\tincludes #{ $incl.join(':') }\n"
	print "\texcludes #{ $excl.join(':') }\n"
	print "\taccess wanted as #{ $want }\n"
	print "\tdeny access\n" if ($deny)
	print "\tnumber of threads #{ $thrd }\n" if ($thrd > 0)

	# check parameters
	ok = true
	ok = false if ($mask == 0)
	ok = false if ($incl[0] == nil)
	if (! ok) then
		print "parameters not acceptable\n"
		exit(1)
	end
end

# the entry point of the example script
prep()
if ($thrd == 0) then
	main(0)
else
	threads = []
	1.upto($thrd) do |count|
		print "starting thread #{ count }\n"
		threads[count - 1] = Thread.new do
			main(count)
		end
	end
	print "waiting for #{ $thrd } threads to end\n"
	threads.each do |t| t.join end
end

# }
# ----- E O F ---------------------------------------------------
