#!/usr/bin/perl
# ----- ExampleThr.pl -------------------------------------------

=head1 NAME

ExampleThr.pl - Dazuko::Obj demonstration script (threaded)

=cut

my $license = '

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

';

=head1 SYNOPSIS

perl ExampleThr.pl [options] [directory ...]

=head1 DESCRIPTION

Dazuko is a means to hook into a machine's file system and can be used
to monitor (log for diagnostic purposes) or intercept (filter based on
scan results) access to data (files and directories).  Dazuko is mostly
used by antivirus scanners to achieve on access scan capabilites.

The ExampleThr.pl script demonstrates how to use the Dazuko::Obj module
while it is different from the ExampleOO.pl script in that it is a
threaded sample application.
There is an Example.pl script which demonstrates the more C like
interface provided by the Dazuko::IO module.

=head1 OPTIONS

Any path specification following the options is taken as an include path
(just like the C<--incl> option).

=over 4

=item --help

Print out a help screen

=item --mask opcode

Add this operation to the access mask.

The I<opcode> parameter can be any of C<open>, C<close>,
C<close_modified>, C<exec>, C<unlink>, C<rmdir>.  Alternatively
a numeric value can be specified which is determined by adding
the appropriate bits for the operations as defined in Dazuko::IO.

This option can be specified multiple times.  Multiple arguments
can be specified when separated with commas.  Of course this only
makes sense for the symbolic opcodes case.

=item --incl path

Adds the specified path to the list of include paths.

This option can be specified multiple times.  Multiple arguments
can be specified when separated with colons.

=item --excl path

Adds the specified path to the list of exclude paths.

This option can be specified multiple times.  Multiple arguments
can be specified when separated with colons.

=item --deny

Deny all handled accesses.

This option is DANGEROUS and should be used with extreme care!

=back

=head1 AUTHOR

Gerhard Sittig <gsittig@antivir.de>

=head1 SEE ALSO

Dazuko::Obj(3)

http://www.dazuko.org/

=cut

use strict;
# use warnings;

package MyDazuko;

use Dazuko::Obj;

use vars qw( $VERSION @ISA );

$VERSION = '0.01';
@ISA = qw( Dazuko::Obj );

sub new($@) {
	my ( $class, @args, ) = @_;
	my ( $proto, $self, );

	$proto = ref($class) || $class;
	$self = $proto->SUPER::new(@args);
	return($self);
}

sub CheckAccessData($$) {
	my ( $self, $acc, ) = @_;
	my ( $deny, );

	# dump the access structure
	$acc->dump();

	# decide whether to deny access
	$deny = $self->{'deny'} ? 1 : 0;
	print "will ", $deny ? "" : "not ", "deny access\n";
	print "\n";

	return($deny);
}

package main;

use Config;
use Getopt::Long;
use Dazuko::IO;

my @mask = qw( );
my @incl = qw( );
my @excl = qw( /proc /dev/null );
my $deny = 0;

my $RUNNING = 1;
$SIG{'INT'} = sub { $RUNNING = 0; };

sub thr_main() {
	my ( $dazuko, );

	$dazuko = MyDazuko->new( 'deny' => $deny, )
		or die ("cannot create dazuko instance\n");

	$dazuko->Register("groupname", "rw")
		or die ("cannot register with dazuko\n");
	$dazuko->AccessMask(@mask)
		or die("cannot set access mask\n");
	$dazuko->Include(@incl)
		or die ("cannot set include path\n");
	$dazuko->Exclude(@excl)
		or die ("cannot set exclude path\n");

	while ($RUNNING && $dazuko->GetAccess()) {
		$dazuko->CheckAccess();
		$dazuko->ReturnAccess();
	}

	$dazuko->Unregister()
		or warn("cannot unregister with dazuko\n");

	1;
}

my $me;
my $numthr = 3;
my %getopt = (
	'help' => sub {
		print "synopsis: $me [options] [incl ...]\n";
		print "\t--mask op\t", "add operation \"op\" to access mask\n";
		print "\t--incl path\t", "include directory \"path\"\n";
		print "\t--excl path\t", "exclude directory \"path\"\n";
		print "\t--deny\t", "deny all accesses\n";
		exit(0);
	},
	'mask=s' => \@mask,
	'incl=s' => \@incl,
	'excl=s' => \@excl,
	'deny!'	=> \$deny,
	'numthr=i' => \$numthr,
);
my $thr;
my @threads;

$Config{usethreads}
	or die("This Perl installation lacks thread support.\n");
eval "use Thread qw( async );"
	or die("cannot \"use Thread;\": $!\n");

( $me = $0 ) =~ s/^.*\///; # basename()
GetOptions(%getopt)
	or die("cannot grok command line\n");
@mask = qw( open close )
	unless (@mask);
@mask = split(",", join(",", @mask));
push @incl, @ARGV;
# push @incl, '.'
# 	unless (@incl);
@incl = split(":", join(":", @incl));
die("need an include path\n")
	unless (@incl);
@excl = split(":", join(":", @excl));

@threads = ();
while (@threads < $numthr) {
	$thr = async(\&thr_main);
	push @threads, $thr;
}
while ($thr = shift @threads) {
	$thr->join();
}

1;

# ----- E O F ---------------------------------------------------
