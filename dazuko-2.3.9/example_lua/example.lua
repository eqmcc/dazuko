-- ---- example.lua ---------------------------------------------
-- sample Lua script, demonstrates how to interface with Dazuko
--
-- synopsis: [lua] example.lua <script> <config>
--
-- Copyright (c) 2005-2007 Gerhard Sittig
-- All rights reserved.
--
-- Redistribution and use in source and binary forms, with or without
-- modification, are permitted provided that the following conditions
-- are met:
--
-- 1. Redistributions of source code must retain the above copyright notice,
-- this list of conditions and the following disclaimer.
--
-- 2. Redistributions in binary form must reproduce the above copyright notice,
-- this list of conditions and the following disclaimer in the documentation
-- and/or other materials provided with the distribution.
--
-- 3. Neither the name of Dazuko nor the names of its contributors may be used
-- to endorse or promote products derived from this software without specific
-- prior written permission.
--
-- THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
-- AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
-- IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
-- ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
-- LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
-- CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
-- SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
-- INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
-- CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
-- ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
-- POSSIBILITY OF SUCH DAMAGE.

require 'dazuko'

local file = arg[1]
local tab = arg[2]
local config

-- the main routine
function main()
	local d, rc, ver

	-- preparation
	d = dazuko.new(config.group, config.mode)
	ver = d:version()
	io.write("module version: ", ver['text'], "\n")
	ver = d:ioversion()
	io.write("IO version: ", ver['text'], "\n")
	rc = d:setaccessmask(config.mask)
	rc = d:addincludepath(unpack(config.includes))
	rc = d:addexcludepath(unpack(config.excludes))

	-- loop getting accesses
	while d:getaccess(config.handler) do
		-- EMPTY
	end

	-- cleanup
	rc = d:removeallpaths()
	rc = d:unregister()
	d = nil
end

-- check parameters
function prep()
	local f

	-- catch signals (they still interrupt getaccess()
	-- but they don't throw exceptions any longer)
	dazuko.swallowsig()

	-- read in and check the configuration (rather paranoid)
	-- (should this use to...() instead of insisting in a type?)
	assert(file, "need a configuration file spec")
	assert(file ~= '', "need a configuration file spec")
	f = loadfile(file)
	assert(f, "cannot load configuration script")
	f()
	assert(tab, "need a configuration bundle name")
	assert(tab ~= '', "need a configuration bundle name")
	config = _G[tab]
	assert(config, "cannot find configuration bundle in script")
	assert(type(config) == 'table', "configuration bundle is not a table")
	assert(type(config.group) == 'string', "field \"group\" is not a string")
	if (config.mask == nil) then config.mask = 'r'; end
	assert(type(config.mode) == 'string', "field \"mode\" is not a string")
	assert(type(config.mask) == 'number', "field \"mask\" is not a number")
	assert(config.mask > 0, "need a non zero access mask")
	assert(type(config.handler) == 'function', "field \"handler\" is not a function")
	if (type(config.includes) == 'string') then
		config.includes = { config.includes }
	end
	assert(type(config.includes) == 'table', "field \"includes\" is not a table")
	table.foreach(config.includes, function(k, v)
		assert(type(v) == 'string', "includes item is not a string")
	end)
	assert(config.includes[1], "need at least one include path")
	if (type(config.excludes) == 'string') then
		config.excludes = { config.excludes }
	end
	assert(type(config.excludes) == 'table', "field \"excludes\" is not a table")
	table.foreach(config.excludes, function(k, v)
		assert(type(v) == 'string', "excludes item is not a string")
	end)

	-- dump parameters
	io.write("will register with group \"", config.group, "\" and mode \"", config.mode, "\"\n")
	io.write("access mask will be ", config.mask, "\n")
	io.write("include directories are:")
	table.foreach(config.includes, function(k, v) io.write("\n\t", v) end)
	io.write("\n")
	io.write("exclude directories are:")
	table.foreach(config.excludes, function(k, v) io.write("\n\t", v) end)
	io.write("\n")
end

-- program entry point
prep()
main()

-- ---- E O F ---------------------------------------------------
