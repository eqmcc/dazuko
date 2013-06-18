#!/usr/bin/env ruby
# == file extconf.rb
# setup instructions for the Dazuko extension,
# 
# the "--forced" cmdline option will ignore missing prerequisites

require 'mkmf'
require 'English'

# this is a hack to make missing libs non fatal for Makefile creation
# (needed when running "ruby extconf.rb" from dazuko's configure)
$forced = false
$ARGV.each do |arg| $forced = true if (arg =~ /--forced/) end
ok = true

# I'd love to add this flag in a different way than munging the $CFLAGS global
$CFLAGS += ' -Wall'

# we need the dazukoio header file and the libdazuko.a library;
# when this ruby extension is built from a different location than
# the example_ruby directory or should be built against a different
# dazuko version, use the --with-dazuko{-include,-lib,}=... option(s)
dir_config('dazuko', '..', '../library')

if (! have_header('dazukoio.h')) then
	exit(1) unless ($forced)
	ok = false
end

if (! have_library('dazuko', 'dazukoGetAccess_TS')) then
	exit(1) unless ($forced)
	ok = false
end

# finally, create the Makefile
print "will create Makefile (ignoring missing prerequisites)\n" if (! ok)
create_makefile("Dazuko")

# ----- E O F ---------------------------------------------------
