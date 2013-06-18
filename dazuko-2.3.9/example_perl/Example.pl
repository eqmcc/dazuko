#!/usr/bin/perl
# ----- Example.pl ----------------------------------------------

=head1 NAME

Example.pl - Dazuko::IO demonstration script

=cut

my $license = '

Copyright (c) 2004, 2005 Gerhard Sittig
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

';

=head1 SYNOPSIS

Example.pl [options] [directory ...]

=head1 DESCRIPTION

Dazuko is a means to hook into a machine's file system and can be used
to monitor (log for diagnostic purposes) or intercept (filter based on
scan results) access to data (files and directories).  Dazuko is mostly
used by antivirus scanners to achieve on access scan capabilites.

The Example.pl script demonstrates how to use the Dazuko::IO module.
There is an ExampleOO.pl script which demonstrates the object oriented
approach provided by the Dazuko::Obj module.

=head1 OPTIONS

Any path specification following the options is taken as an include path
(just like the C<--incl> option).

=over 4

=item --help

Print out a help screen

=item --mask number

Set the access mask to this value.  The numeric parameter
is determined by adding the appropriate bits for the
operations as defined in Dazuko::IO (the C<DAZUKO_ON_*> values).

=item --incl path

Adds the specified path to the list of include paths.

This option can be specified multiple times.  Multiple arguments
can be specified when separated with colons.

=item --excl path

Adds the specified path to the list of exclude paths.

This option can be specified multiple times.  Multiple arguments
can be specified when separated with colons.

=back

=head1 AUTHOR

Gerhard Sittig <gsittig@antivir.de>

=head1 SEE ALSO

Dazuko::IO(3)

http://www.dazuko.org/

=cut

use strict;
# use warnings;

use Getopt::Long;
use Dazuko::IO qw( $DAZUKO_ON_OPEN $DAZUKO_ON_CLOSE );

my $me;
my $mask = $DAZUKO_ON_OPEN | $DAZUKO_ON_CLOSE;
my @incl = ();
my @excl = ();
my $rc;
my $path;
my $RUNNING = 1;
my @arr;
my $vtxt;
my @vnum;
my %getopt = (
	'help' => sub {
		print "synopsis: $me [options] [incl ...]\n";
		print "\t--mask n\t", "use access mask \"n\"\n";
		print "\t--incl path\t", "include directory \"path\"\n";
		print "\t--excl path\t", "exclude directory \"path\"\n";
		exit(0);
	},
	'mask=i' => \$mask,
	'incl=s' => \@incl,
	'excl=s' => \@excl,
);

$me = $0;
$me =~ s/^.*\///; # basename()
GetOptions(%getopt)
	or die("cannot grok command line\n");
push @incl, @ARGV;
@incl = split(":", join(":", @incl));
@excl = split(":", join(":", @excl));
die("need an include path\n")
	unless (@incl);

( $vtxt, @vnum, ) = &Dazuko::IO::IOVersion();
print "DazukoIO version \"$vtxt\" (" . join('.', @vnum) . ")\n"
	if ($vtxt);

&Dazuko::IO::Register("groupname", "rw") == 0
	or die("cannot register with dazuko\n");

( $vtxt, @vnum, ) = &Dazuko::IO::Version();
print "Dazuko version \"$vtxt\" (" . join('.', @vnum) . ")\n"
	if ($vtxt);

&Dazuko::IO::SetAccessMask($mask) == 0
	or warn("cannot set access mask\n");

$RUNNING = 1;
foreach $path (@incl) {
	&Dazuko::IO::AddIncludePath($path) == 0
		or warn("cannot set include path\n"), $RUNNING = 0;
}
foreach $path (@excl) {
	&Dazuko::IO::AddExcludePath($path) == 0
		or warn("cannot set exclude path\n"), $RUNNING = 0;
}

$SIG{'INT'} = sub { $RUNNING = 0; };
while (($RUNNING) && (@arr = &Dazuko::IO::GetAccess())) {
	my (
		$acc, $deny, $event,
		$flags, $mode, $uid, $pid,
		$filename, $filesize,
		$fileuid, $filegid,
		$filemode, $filedevice,
	) = @arr;

	if (defined $acc) {
		print "got an access, data:";
		print " event $event" if (defined $event);
		print " flags $flags" if (defined $flags);
		print " mode $mode" if (defined $mode);
		print " uid $uid" if (defined $uid);
		print " pid $pid" if (defined $pid);
		print " filename \"$filename\"" if (defined $filename);
		print " filesize $filesize" if (defined $filesize);
		print " fileuid $fileuid" if (defined $fileuid);
		print " filegid $filegid" if (defined $filegid);
		print " filemode $filemode" if (defined $filemode);
		print " filedevice $filedevice" if (defined $filedevice);
		print ".\n";
	}

	&Dazuko::IO::ReturnAccess($acc, 0) == 0
		or warn("cannot return access\n"), $RUNNING = 0;
}

&Dazuko::IO::Unregister() == 0
	or warn("cannot unregister with dazuko\n");

1;

# ----- E O F ---------------------------------------------------
