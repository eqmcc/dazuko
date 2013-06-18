# ----- Obj.pm --------------------------------------------------
# Perl extension to Dazuko, OO style

use strict;

package Dazuko::Obj;

=head1 NAME

Dazuko::Obj - Perl extension for Dazuko (OO style)

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

  use Dazuko::Obj;

  # setup
  $dazuko = Dazuko::Obj->new();
  $dazuko->Register("Vendor:App", "rw");
  $dazuko->AccessMask('open', 'close');
  $dazuko->Include( qw( /home /data ) );
  $dazuko->Exclude( qw( /dev/ /proc/ ) );

  # main loop, make sure to spend as little time as possible
  # when holding the access -- the kernel is waiting for you!
  while ($dazuko->GetAccess()) {
    $dazuko->CheckAccess();
    $dazuko->ReturnAccess();
  }

  # cleanup
  $dazuko->Unregister();
  $dazuko = undef;

=head1 DESCRIPTION

Dazuko is a means to hook into a machine's file system and can be used
to monitor (log for diagnostic purposes) or intercept (filter based on
scan results) access to data (files and directories).  Dazuko is mostly
used by antivirus scanners to achieve on access scan capabilites.

The C<Dazuko::Obj> module provides an object oriented Perl interface to
Dazuko.  You should derive a subclass and implement your own
C<CheckAccessData()> method which operates on the passed in
C<Dazuko::Access> object to decide whether to deny or allow access
(or to simply log these parameters when implementing a monitor, not
a scanner or filter).

=cut

use Dazuko::IO;
use Dazuko::Access;

use vars qw( $VERSION );

$VERSION = '0.01';

=head1 METHODS

The Dazuko::Obj package provides the following methods:

=cut

=over 4

=item new()

The C<new()> constructor creates a new object instance.

=back

=cut

sub new($@) {
	my ( $class, @args, ) = @_;
	my ( $proto, @mask, @incl, @excl, $self, );
	my ( @vers, @iovers, );

	$proto = ref($class) || $class;
	@mask = ();
	@incl = ();
	@excl = ();
	@vers = ();
	@iovers = ();
	$self = {
		'group' => undef,
		'mode' => undef,
		'mask' => \@mask,
		'incl' => \@incl,
		'excl' => \@excl,
		'daz_tid' => undef,
		'acc_ref' => undef,
		'acc_data' => undef,
		'vers' => \@vers,
		'iovers' => \@iovers,
		@args,
	};
	bless $self, $proto;
	return($self);
}

=over 4

=item Register($group, $mode)

The C<Register()> method registers your application with the
kernel module.  The I<$group> parameter should have the form
"vendor:application", the I<$mode> parameter may be F<"r"> for
read only (log) mode or F<"rw"> for read and write (scanner,
filter) mode.  The C<$mode> parameter is optional and defaults
to F<"r">.

Note that in read only mode you only learn about accesses but
cannot block (deny) them.

=back

=cut

sub Register($$$) {
	my ( $self, $group, $mode, ) = @_;
	my ( $id, );

	$group = "DazukoPerl"
		unless ($group);
	$mode = "r"
		unless ($mode);
	$id = Dazuko::IO::Register_TS($group, $mode);
	return(undef)
		unless (defined $id);
	$self->{'daz_tid'} = $id;
	$self->{'group'} = $group;
	$self->{'mode'} = $mode;
	1;
}

=over 4

=item Unregister()

The C<Unregister()> method unregisters your application with the
kernel module.

=back

=cut

sub Unregister($) {
	my ( $self, ) = @_;
	my ( $rc, );

	$rc = Dazuko::IO::Unregister_TS($self->{'daz_tid'});
	return(undef)
		unless ($rc == 0);
	$self->{'daz_tid'} = undef;
	1;
}

=over 4

=item Version(), IOVersion()

The C<Version()> method returns the module's version information
(kernel space part).  The C<IOVersion()> method returns the IO
lib's version information (user space part).

The information is returned in an array which consists of one
string and four numbers.

=back

=cut

sub Version($) {
	my ( $self, ) = @_;

	@{$self->{'vers'}} = Dazuko::IO::Version()
		if (! @{$self->{'vers'}});

	return(@{$self->{'vers'}});
}

sub IOVersion($) {
	my ( $self, ) = @_;

	@{$self->{'iovers'}} = Dazuko::IO::IOVersion()
		if (! @{$self->{'iovers'}});

	return(@{$self->{'iovers'}});
}

=over 4

=item AccesMask($bits) or AccessMask(@opcodes)

The C<AccessMask()> method queries or sets the kind of accesses
the application should get.

Since this method always returns the currently used mask an empty
parameter list can be used to query previously set masks.

Setting the mask can be done by either passing a single numerical
value (a bit mask like the one the C interface uses, C<Dazuko::IO>
has appropriate declarations you can OR together) or a list of
symbolic opcodes (like C<qw( open close )>).

=back

=cut

sub AccessMask($@) {
	my ( $self, @mask, ) = @_;
	my ( $bits, $id, $num, $rc, );

	if (@mask) {
		if ((@mask == 1) && ($mask[0] =~ /^\d+$/)) {
			$bits = $mask[0];
		} else {
			$bits = 0;
			foreach $id (@mask) {
				$id = 'DAZUKO_ON_' . uc($id);
				$id = '$Dazuko::IO::' . $id;
				eval("\$num = $id;")
					or return(undef);
				$bits |= $num;
			}
		}
		$rc = Dazuko::IO::SetAccessMask_TS($self->{'daz_tid'}, $bits);
		$self->{'mask'} = \@mask
			if ($rc == 0);
	}
	return($self->{'mask'});
}

=over 4

=item Include(@paths)

The C<Include()> method adds a list of path specs to the kernel
module's include list.  It returns the current list of all include
paths (an empty parameter list can thus be used to query this list).

=back

=cut

sub Include($@) {
	my ( $self, @paths, ) = @_;
	my ( $path, $rc, );

	if (@paths) {
		foreach $path (@paths) {
			$rc = Dazuko::IO::AddIncludePath_TS($self->{'daz_tid'}, $path);
			push @{$self->{'incl'}}, $path
				if ($rc == 0);
		}
	}
	return(@{$self->{'incl'}});
}

=over 4

=item Exclude(@paths)

The C<Exclude()> method adds a list of path specs to the kernel
module's exclude list.  It returns the current list of all exclude
paths (an empty parameter list can thus be used to query this list).

=back

=cut

sub Exclude($@) {
	my ( $self, @paths, ) = @_;
	my ( $path, $rc, );

	if (@paths) {
		foreach $path (@paths) {
			$rc = Dazuko::IO::AddExcludePath_TS($self->{'daz_tid'}, $path);
			push @{$self->{'excl'}}, $path
				if ($rc == 0);
		}
	}
	return(@{$self->{'excl'}});
}

=over 4

=item RemoveAllPaths()

The C<RemoveAllPaths()> method clears the path list (includes
and excludes) of the kernel module.

=back

=cut

sub RemovePaths($) {
	my ( $self, ) = @_;
	my ( $rc, );

	$rc = Dazuko::IO::RemoveAllPaths_TS($self->{'daz_tid'});
	return(undef)
		if ($rc != 0);
	$self->{'incl'} = [];
	$self->{'excl'} = [];
	return(1);
}

=over 4

=item GetAccess()

The C<GetAccess()> method waits until a file access according to the
configured C<AccessMask()> happens in or under one of the configured
C<Include()> paths but not in or under a configured C<Exclude()> path.
The parameters of the access are stored internally and usually get
handled in C<CheckAccessData()>.  The method returns a C<Dazuko::Access>
object or C<undef> in the case of failure.

BEWARE:  Accesses gotten from the kernel in read and write mode MUST
be returned to the kernel by means of C<ReturnAccess()>, otherwise
you may risk your system's stability!  Note that the kernel blocks
the file access while you handle it, so take care to spend as little
time as necessary in this state.

=back

=cut

sub GetAccess($) {
	my ( $self, ) = @_;
	my ( $ref, @arr, $acc, );

	# return outstanding accesses
	# XXX scream louder at so bad a programming mistake?
	$ref = $self->{'acc_ref'};
	Dazuko::IO::ReturnAccess_TS($self->{'daz_tid'}, $ref, 0)
		if (defined $ref);

	# get a new access
	@arr = Dazuko::IO::GetAccess_TS($self->{'daz_tid'})
		or return(undef);
	$self->{'acc_ref'} = shift(@arr);
	$acc = Dazuko::Access->new(
		'deny'		=> $arr[ 0],
		'event'		=> $arr[ 1],
		'flags'		=> $arr[ 2],
		'mode'		=> $arr[ 3],
		'uid'		=> $arr[ 4],
		'pid'		=> $arr[ 5],
		'filename'	=> $arr[ 6],
		'filesize'	=> $arr[ 7],
		'fileuid'	=> $arr[ 8],
		'filegid'	=> $arr[ 9],
		'filemode'	=> $arr[10],
		'filedevice'	=> $arr[11],
	);
	$self->{'acc_data'} = $acc;
	return($acc);
}

=over 4

=item CheckAccess()

The C<CheckAccess()> method inspects the data gathered by
C<GetAccess()> and stores the information whether to allow or
deny access for the later call to C<ReturnAccess()>.  Internally
it makes use of the C<CheckAccessData()> method which you should
override for your own applications.

=back

=cut

sub CheckAccess($) {
	my ( $self, ) = @_;
	my ( $acc, $deny, );

	$acc = $self->{'acc_data'};
	return(undef)
		unless (defined $acc);
	$deny = $self->CheckAccessData($acc);
	$acc->deny($deny);
	return($deny);
}

=over 4

=item CheckAccessData($acc)

The C<CheckAccessData()> method is invoked by C<CheckAccess()> and
is the method actually carrying out the real work.  The C<Dazuko::Access>
object gets passed in, the deny status is returned (0 means allow access,
1 or non zero means deny access).

When writing Dazuko enabled Perl programs you should derive a subclass
from C<Dazuko::Obj> and implement your own C<CheckAccessData()> method.
This is the easiest and most comfortable way to hook up with Dazuko and
is demonstrated in the OO example provided with the source code of this
Perl extension.

=back

=cut

sub CheckAccessData($$) {
	my ( $self, $acc, ) = @_;

	# actually should take a look at $acc and decide
	# whether access should be denied (1) or allowed(0)

	return(0);
}

=over 4

=item ReturnAccess()

The C<ReturnAccess()> method returns an access gathered by C<GetAccess()>
and hands the deny state back to the kernel module.

Note that you MUST return accesses back to the kernel since it is
waiting for you.  Failing to return accesses will put the system into
an unstable condition where it might block or hang.

=back

=cut

sub ReturnAccess($) {
	my ( $self, ) = @_;
	my ( $ref, $acc, $deny, $rc, );

	$ref = $self->{'acc_ref'};
	return(undef)
		unless (defined $ref);
	$acc = $self->{'acc_data'};
	$deny = (defined $acc) ? $acc->{'deny'} : 0;
	$deny = 0 unless (defined $deny);
	$rc = Dazuko::IO::ReturnAccess_TS($self->{'daz_tid'}, $ref, $deny);
	if ($rc == 0) {
		$self->{'acc_ref'} = undef;
		$self->{'acc_data'} = undef;
	}
	1;
}

1;
__END__

=head1 AUTHOR

Gerhard Sittig <gsittig@antivir.de>

=head1 SEE ALSO

Dazuko::Access(3), Dazuko::IO(3)

http://www.dazuko.org/

=cut

# ----- E O F ---------------------------------------------------
