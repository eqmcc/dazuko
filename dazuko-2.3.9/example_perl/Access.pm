# ----- Access.pm -----------------------------------------------
# Perl extension to Dazuko, event data container

use strict;

package Dazuko::Access;

=head1 NAME

Dazuko::Access - Perl extension for Dazuko (event data container)

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

  use Dazuko::Access;

  $acc = Dazuko::Access->new( 'event' => 1, 'filename' => "/dev/null", );
  $acc->dump();
  $acc->deny(1);
  print $acc->deny();

=head1 DESCRIPTION

Dazuko is a means to hook into a machine's file system and can be used
to monitor (log for diagnostic purposes) or intercept (filter based on
scan results) access to data (files and directories).  Dazuko is mostly
used by antivirus scanners to achieve on access scan capabilites.

The Dazuko::Access module holds data about an event and gets used by the
Dazuko::Obj package.

=cut

use vars qw( $VERSION );

$VERSION = '0.01';

=head1 METHODS

The Dazuko::Access package provides the following methods:

=cut

=over 4

=item new()

The C<new()> constructor creates a new object instance.  Initial
values for the object's properties can be passed in.

  $acc = Dazuko::Access->new();
  $acc = Dazuko::Access->new( 'event' => 1, 'filename' => "/dev/null", );

=back

=cut

sub new($@) {
	my ( $class, @args, ) = @_;
	my ( $proto, $self, );

	$proto = ref($class) || $class;
	$self = {
		'deny'		=> undef,
		'event'		=> undef,
		'flags'		=> undef,
		'mode'		=> undef,
		'uid'		=> undef,
		'pid'		=> undef,
		'filename'	=> undef,
		'filesize'	=> undef,
		'fileuid'	=> undef,
		'filegid'	=> undef,
		'filemode'	=> undef,
		'filedevice'	=> undef,
		@args,
	};
	bless $self, $proto;
	return($self);
}

=over 4

=item dump()

The C<dump()> method prints out the event parameters held by the
container.

=back

=cut

sub dump($) {
	my ( $self, ) = @_;
	my ( $key, $val, );

	foreach $key (sort keys %{$self}) {
		$val = $self->{$key};
		print "'$key' => $val\n"
			if (defined $val);
	}
}

=over 4

=item deny($flag)

The C<deny()> method is a convenience wrapper to the "deny"
property of the access.  It serves as a set and get accessor.
The current value of the deny parameter is always returned.  An
optional new value can be passed in.

  $acc->deny(1);
  print $acc->deny();

=back

=cut

sub deny($$) {
	my ( $self, $val, ) = @_;

	$self->{'deny'} = $val ? 1 : 0
		if (defined $val);
	return($self->{'deny'});
}

1;

__END__

=head1 AUTHOR

Gerhard Sittig <gsittig@antivir.de>

=head1 SEE ALSO

Dazuko::Obj(3)

http://www.dazuko.org/

=cut

# ----- E O F ---------------------------------------------------
