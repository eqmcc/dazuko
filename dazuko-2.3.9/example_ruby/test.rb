#!/usr/bin/env ruby
# == file test.rb
# unit test for the Dazuko extension

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

require 'test/unit'
require 'English'
require 'Dazuko'

# == class DazukoTest
# implements the unit test for the Dazuko class
class DazukoTest < Test::Unit::TestCase

	# check all values are initialized correctly
	def test_init_defaults
		d = Dazuko.new
		assert(d != nil)

		assert(d.group == nil)
		assert(d.mode == nil)
		assert(d.mask == nil)
		assert(d.incl == nil)
		assert(d.excl == nil)
		assert(d.silent? == false)
		assert(d.access_want? == "Hash")

		d = nil
	end

	# check that an unregistered instance cannot be configured or used
	def test_unreg_config
		d = Dazuko.new
		assert(d != nil)
		d.silent(true)

		# NO d.register() call
		assert(d.set_mask(Dazuko::DAZUKO_ON_OPEN) == false)
		assert(d.add_include('/incl') == false)
		assert(d.add_exclude('/excl') == false)
		assert(d.remove_paths() == false)
		assert(d.get_access() do |acc| 0 end == false)
		assert(d.unregister() == false)

		d = nil
	end

	# check that configured parameters can be queried
	# (are echoed back correctly, some of them accumulated)
	def test_setup_echo
		d = Dazuko.new
		assert(d != nil)

		assert(d.register("example:ruby", "r") == true)
		assert(d.group == "example:ruby")
		assert(d.mode == "r")

		assert(d.mask == 0)
		assert(d.set_mask(Dazuko::DAZUKO_ON_OPEN) == true)
		assert(d.mask == Dazuko::DAZUKO_ON_OPEN)
		assert(d.set_mask(Dazuko::DAZUKO_ON_CLOSE) == true)
		assert(d.mask == Dazuko::DAZUKO_ON_CLOSE)

		assert(d.incl == [])
		assert(d.add_include("/include1") == true)
		assert(d.incl == [ "/include1" ])
		assert(d.add_include([ "/include2", "/include3" ]) == true)
		assert(d.incl == [ "/include1", "/include2", "/include3" ])

		assert(d.excl == [])
		assert(d.add_exclude("/exclude1") == true)
		assert(d.excl == [ "/exclude1" ])
		assert(d.add_exclude([ "/exclude2", "/exclude3" ]) == true)
		assert(d.excl == [ "/exclude1", "/exclude2", "/exclude3" ])

		assert(d.remove_paths() == true)
		assert(d.incl == [])
		assert(d.excl == [])

		assert(d.unregister() == true)
		assert(d.group == nil)
		assert(d.mode == nil)
		assert(d.mask == nil)
		assert(d.incl == nil)
		assert(d.excl == nil)

		d = nil
	end

	# test parameter count and conversion at the interface
	def test_param_conv
		d = Dazuko.new
		assert(d != nil)

		d.silent(true)

		assert(d.register("example:ruby") == true)
		assert(d.mode == "r")

		assert(d.incl == [])
		assert(d.add_include() == true)
		assert(d.incl == [])
		assert(d.add_include(nil) == true)
		assert(d.incl == [])
		assert(d.add_include([ nil ]) == true)
		assert(d.incl == [])
		assert(d.add_include([ '/i1' ], '/i2') == false)
		assert(d.incl == [])
		assert(d.add_include([ '/i1', '/i2' ]) == true)
		assert(d.incl == [ '/i1', '/i2' ])
		assert(d.add_include('/i3', '/i4') == true)
		assert(d.incl == [ '/i1', '/i2', '/i3', '/i4' ])

		assert(d.silent(true) != nil)
		assert(d.silent? == true)
		assert(d.silent(false) != nil)
		assert(d.silent? == false)
		assert(d.silent(1) != nil)
		assert(d.silent? == true)
		assert(d.silent(0) != nil)
		assert(d.silent? == false)

		assert(d.access_want("Array") != nil)
		assert(d.access_want? == "Array")
		assert(d.access_want("Hash") != nil)
		assert(d.access_want? == "Hash")
		assert(d.access_want([]) != nil)
		assert(d.access_want? == "Array")
		assert(d.access_want({}) != nil)
		assert(d.access_want? == "Hash")

		assert(d.unregister() == true)

		d = nil
	end

	# test a regular (correct) use, without access
	# (this is "harmless" and will never block)
	def test_without_access
		d = Dazuko.new
		assert(d != nil)

		assert(d.register("example:ruby", "r") == true)
		assert(d.set_mask(Dazuko::DAZUKO_ON_OPEN) == true)
		assert(d.add_include("/include1") == true)
		assert(d.add_include([ "/include2", "/include3" ]) == true)
		assert(d.add_exclude("/exclude1") == true)
		assert(d.add_exclude([ "/exclude2", "/exclude3" ]) == true)
		assert(d.excl == [ "/exclude1", "/exclude2", "/exclude3" ])
		assert(d.remove_paths() == true)
		assert(d.incl == [])
		assert(d.excl == [])
		assert(d.unregister() == true)

		d = nil
	end

	# helper method, determines the absolute path for its input
	def help_make_absolute(fn)
		fn = File.expand_path(fn)
		return(fn)
	end

	# helper method, will schedule a delayed access to the file
	def help_schedule_access(fn, delay = 0.1)
		return fork do
			# the unit test frame dies if wo DON'T
			$stdin.close
			$stdout.close
			$stderr.close

			# sleep for a while
			sleep(delay)

			# try to access the file
			rc = 0
			begin
				f = File.open(fn, 'r')
				d = f.read(512)
				rc = 0
			rescue
				rc = 1
			end

			# return a success/failure code
			exit(rc)
		end
	end

	# helper method, get the exit code for a child
	def help_exitcode_for_pid(pid)
		# did not work: [ id, rc ] = Process.waitpid2(pid, 0)
		a = Process.waitpid2(pid, 0)
		id = a[0]
		rc = a[1]
		return(nil) if (id != pid)
		return(rc)
	end

	# test a regular (correct) use, with access
	# (will block until an access occurs,
	# tries to unblock itself by scheduling an access)
	def test_withaccess
		file = $PROGRAM_NAME
		file = help_make_absolute(file)

		d = Dazuko.new
		assert(d != nil)

		assert(d.register("example:ruby", "r") == true)
		assert(d.set_mask(Dazuko::DAZUKO_ON_OPEN) == true)
		assert(d.add_include(file) == true)
		assert(d.add_exclude("/dev/") == true)

		pid = help_schedule_access(file)
		rc = d.get_access() do |acc|
			assert(acc != nil)
			assert(((acc.class == Hash) or (acc.class == Array)));
			0
		end
		assert(rc == true)
		help_exitcode_for_pid(pid)

		assert(d.unregister() == true)

		d = nil
	end

	# test the event details presentation
	# (check if we get data in the form we requested)
	def test_access_repr
		file = $PROGRAM_NAME
		file = help_make_absolute(file)

		d = Dazuko.new
		assert(d != nil)

		assert(d.register("example:ruby", "r") == true)
		assert(d.set_mask(Dazuko::DAZUKO_ON_OPEN) == true)
		assert(d.add_include(file) == true)
		assert(d.add_exclude("/dev/") == true)

		assert(d.access_want("Array") != nil)
		pid = help_schedule_access(file)
		rc = d.get_access() do |acc|
			assert(acc.class == Array)
			assert(acc[0] == 0)
			assert(acc[5] == pid)
			assert(acc[6] == file)
			0
		end
		assert(rc == true)
		help_exitcode_for_pid(pid)

		assert(d.access_want("Hash") != nil)
		pid = help_schedule_access(file)
		rc = d.get_access() do |acc|
			assert(acc.class == Hash)
			assert(acc['deny'] == 0)
			assert(acc['pid'] == pid)
			assert(acc['filename'] == file)
			0
		end
		assert(rc == true)
		help_exitcode_for_pid(pid)

		assert(d.unregister() == true)

		d = nil
	end

	# helper routine: registers in "rw" mode, gets an access and checks
	# if a given handler return value allows one to access a file
	def help_handle_rw_access(ret_deny, exp_success)
		file = $PROGRAM_NAME
		file = help_make_absolute(file)

		d = Dazuko.new
		assert(d != nil)

		assert(d.register("example:ruby", "rw") == true)
		assert(d.set_mask(Dazuko::DAZUKO_ON_OPEN) == true)
		assert(d.add_include(file) == true)
		assert(d.add_exclude("/dev/") == true)
		assert(d.access_want("Hash") != nil)

		# numerical, 0 => grant
		pid = help_schedule_access(file)
		rc = d.get_access() do |acc|
			assert(acc.class == Hash)
			assert(acc['deny'] == 0)
			assert(acc['pid'] == pid)
			assert(acc['filename'] == file)
			ret_deny
		end
		assert(rc == true)
		rc = help_exitcode_for_pid(pid)
		assert(rc != nil)
		ok = (rc == 0)
		assert(ok == exp_success)

		assert(d.unregister() == true)

		d = nil
	end

	# all the test_denyaccess_*() routines test if deny works,
	# while they check with different types of return values
	def test_denyaccess_num0
		help_handle_rw_access(0, true)
	end

	def test_denyaccess_num1
		help_handle_rw_access(1, false)
	end

	def test_denyaccess_false
		help_handle_rw_access(false, true)
	end

	def test_denyaccess_true
		help_handle_rw_access(true, false)
	end

	def test_denyaccess_str0
		help_handle_rw_access('0', true)
	end

	def test_denyaccess_str1
		help_handle_rw_access('1', false)
	end

	def test_denyaccess_strfalse
		help_handle_rw_access('false', true)
	end

	def test_denyaccess_strtrue
		help_handle_rw_access('true', false)
	end

	def test_denyaccess_strno
		help_handle_rw_access('no', true)
	end

	def test_denyaccess_stryes
		help_handle_rw_access('yes', false)
	end

	def test_denyaccess_nil
		help_handle_rw_access(nil, true)
	end

	# test the event handler's exception catching
	# (access will be denied should the application fail)
	def test_access_exception
		file = $PROGRAM_NAME
		file = help_make_absolute(file)

		d = Dazuko.new
		assert(d != nil)

		assert(d.register("example:ruby", "rw") == true)
		assert(d.set_mask(Dazuko::DAZUKO_ON_OPEN) == true)
		assert(d.add_include(file) == true)
		assert(d.add_exclude("/dev/") == true)
		assert(d.access_want("Hash") != nil)
		assert(d.silent("really_only_for_the_unit_test") != nil)

		# exception => deny
		pid = help_schedule_access(file)
		rc = d.get_access() do |acc|
			assert(acc.class == Hash)
			assert(acc['deny'] == 0)
			assert(acc['pid'] == pid)
			assert(acc['filename'] == file)
			throw "access handler oops"
			# UNREACH
			assert(false)
		end
		assert(rc == true)
		rc = help_exitcode_for_pid(pid)
		assert(rc != nil)
		assert(rc != 0)

		assert(d.unregister() == true)

		d = nil
	end

end

# ----- E O F ---------------------------------------------------
