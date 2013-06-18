# ----- IO.pm ---------------------------------------------------
# Perl extension to Dazuko, XS glue

use strict;

package Dazuko::IO;

=head1 NAME

Dazuko::IO - Perl extension for Dazuko (procedural style)

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

  use Dazuko::IO qw( $DAZUKO_ON_OPEN $DAZUKO_ON_CLOSE );

  # setup
  Dazuko::IO::Register("Vendor:App", "rw");
  Dazuko::IO::SetAccessMask($DAZUKO_ON_OPEN | $DAZUKO_ON_CLOSE);
  foreach $path (qw( /home /data )) {
    Dazuko::IO::AddIncludePath($path);
  }
  foreach $path (qw( /dev/ /proc/ )) {
    Dazuko::IO::AddExcludePath($path);
  }

  # main loop, make sure to spend as little time as possible
  # when holding the access -- the kernel is waiting for you!
  while (@acc = Dazuko::IO::GetAccess()) {
    ( $ref, $deny, $event, $flags, $mode, $uid,
      $pid, $filename, $filesize, $fileuid,
      $filegid, $filemode, $filedevice, ) = @acc;
    $deny = &checkAccess(...);
    Dazuko::IO::ReturnAccess($ref, $deny);
  }

  # cleanup
  Dazuko::IO::Unregister();

=head1 DESCRIPTION

Dazuko is a means to hook into a machine's file system and can be used
to monitor (log for diagnostic purposes) or intercept (filter based on
scan results) access to data (files and directories).  Dazuko is mostly
used by antivirus scanners to achieve on access scan capabilites.

The Dazuko::IO module provides a procedural Perl interface to Dazuko.  The
Dazuko::Obj module builds upon this module and provides a more Perl style
object oriented interface to dazuko.

=cut

use Carp;

use vars qw(
	$VERSION @ISA
	@EXPORT @EXPORT_OK
	$DAZUKO_ON_OPEN
	$DAZUKO_ON_CLOSE
	$DAZUKO_ON_EXEC
	$DAZUKO_ON_CLOSE_MODIFIED
	$DAZUKO_ON_UNLINK
	$DAZUKO_ON_RMDIR
);

require Exporter;
require DynaLoader;

@ISA = qw( Exporter DynaLoader );
@EXPORT = qw(
	$DAZUKO_ON_OPEN
	$DAZUKO_ON_CLOSE
	$DAZUKO_ON_EXEC
	$DAZUKO_ON_CLOSE_MODIFIED
	$DAZUKO_ON_UNLINK
	$DAZUKO_ON_RMDIR
);
$VERSION = '0.01';

=head1 CONSTANTS

The bit mask for the access operations passed to C<SetAccessMask()>
can be ORed together with the following predefined values:

  $DAZUKO_ON_OPEN
  $DAZUKO_ON_CLOSE
  $DAZUKO_ON_EXEC
  $DAZUKO_ON_CLOSE_MODIFIED
  $DAZUKO_ON_UNLINK
  $DAZUKO_ON_RMDIR

=cut

# these were suggested to be exported by AUTOLOAD and constant() but
# I could not figure out how to make this work with "use strict"; so
# let's take the minor pain to sync these with dazukoio.h ...
$DAZUKO_ON_OPEN			= 1 << 0;
$DAZUKO_ON_CLOSE		= 1 << 1;
$DAZUKO_ON_EXEC 		= 1 << 2;
$DAZUKO_ON_CLOSE_MODIFIED	= 1 << 3;
$DAZUKO_ON_UNLINK		= 1 << 4;
$DAZUKO_ON_RMDIR		= 1 << 5;

=head1 ROUTINES

This modules implements the following routines:

=over 4

=item Register($group, $mode)

The C<Register()> routine registers your application with the
kernel module.  The I<$group> parameter should have the form
"vendor:application", the I<$mode> parameter may be F<"r"> for
read only (log) mode or F<"rw"> for read and write (scanner,
filter) mode.

Note that in read only mode you only learn about accesses but
cannot block (deny) them.

The routine returns 0 for success, negative values otherwise.

=item Unregister()

The C<Unregister()> routine unregisters your application with the
kernel module.

The routine returns 0 for success, negative values otherwise.

=item Version(), IOVersion()

The C<Version()> routine returns the version information for the
kernel space part of Dazuko, the C<IOVersion()> routine returns
the version information for the user space part of Dazuko.

The version information is returned as an array which consists
of one string (text representation of the information) and four
numbers (major, minor, revision and release).

=item SetAccessMask($mask)

The C<SetAccessMask()> routine sets the kind of accesses
the application should get.  The I<$mask> parameter should be
determined by ORing together the above C<DAZUKO_ON_*> values.

The routine returns 0 for success, negative values otherwise.

=item AddIncludePath($path)

The C<AddIncludePath()> routine adds a path spec to the kernel
module's include list.

The routine returns 0 for success, negative values otherwise.

=item AddExcludePath($path)

The C<AddExcludePath()> routine adds a path spec to the kernel
module's exclude list.

The routine returns 0 for success, negative values otherwise.

=item RemoveAllPaths()

The C<RemoveAllPaths()> routine clears the path list (includes
and excludes) of the kernel module.

The routine returns 0 for success, negative values otherwise.

=item GetAccess()

The C<GetAccess()> routine waits until a file access according to the
configured access mask happens in or under one of the configured
include paths but not in or under a configured exclude path.

The parameters of the access are returned in a list which is empty
in case of failures.  On successful operation the returned list
consists of a reference to be passed back into C<ReturnAccess>,
an up to this moment determined deny state (might have been
influenced by other Dazuko enabled applications), the type of
access event and event specific data: flags of the file operation,
permission bits for the file operation, UID and PID of the process
carrying out the access, the name, the size, the owning UID and GID,
the permission bits of the file which is accessed and the device
the file lives on (in this order, see the SYNOPSIS section for an
example of how to read the list).  Note that not every event will
have valid or useful values for every parameter.

BEWARE:  Accesses gotten from the kernel in read and write mode MUST
be returned to the kernel by means of C<ReturnAccess()>, otherwise
you may risk your system's stability!  Note that the kernel blocks
the file access while you handle it, so take care to spend as little
time as necessary in this state.

=item ReturnAccess($acc, $deny)

The C<ReturnAccess()> routine returns an access gathered by C<GetAccess()>
and hands the deny state back to the kernel module.  The C<$acc> parameter
is the first list element returned by C<GetAccess()>.  The C<$deny>
parameter is optional and specifies whether to deny (non zero) or
allow (zero) the file operation, by default the access is allowed.

The routine returns 0 for success, negative values otherwise.

Note that you MUST return accesses back to the kernel since it is
waiting for you.  Failing to return accesses will put the system into
an unstable condition where it might block or hang.

=item *_TS variants

Thread safe variants of all the above routines are available, too.  They
are idential to their thread unaware counterparts except that the routine's
name has a C<_TS> suffix and they have an additional first C<$id> argument
which holds a thread id.

This id is created with the C<Register_TS()> routine and becomes invalid
with the C<Unregister_TS()> routine.  Every invocation in between needs
to be given this id to pass it down to dazuko.

  $id = Register_TS($group, $mode);
  $rc = SetAccessMask_TS($id, $mask);
  $rc = AddIncludePath_TS($id, $path);
  $rc = AddExcludePath_TS($id, $path);
  $rc = RemoveAllPaths_TS($id);
  $rc = GetAccess_TS($id);
  $rc = ReturnAccess_TS($id, $acc, $deny);
  $rc = Unregister_TS($id);
  $id = undef;

=back

=cut

bootstrap Dazuko::IO $VERSION;

1;
__END__

=head1 AUTHOR

Gerhard Sittig <gsittig@antivir.de>

=head1 SEE ALSO

Dazuko::Obj(3)

http://www.dazuko.org/

=cut

# ----- E O F ---------------------------------------------------
