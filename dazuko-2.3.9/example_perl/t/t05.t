#!/usr/bin/perl
# ----- t05.t ---------------------------------------------------
# vim:set syntax=perl:

# test suite for the Dazuko::IO::*_TS() routines

use strict;

my $loaded = 0;

BEGIN { $| = 1; print "1..11\n"; }
use Dazuko::IO qw( $DAZUKO_ON_OPEN $DAZUKO_ON_CLOSE );
$loaded = 1;
print "ok 1\n";
END { print "not ok 1\n" unless $loaded; }

my (
	@acc, $rc, $group, $mode, $mask, $path, $ref, $deny,
	$event, $flags, $uid, $pid, $filename, $filesize,
	$fileuid, $filegid, $filemode, $filedevice, $id,
);

# fetch in the get_abs_cwd() and schedule_access() routines
eval {
	my $fn;
	$fn = $0;
	$fn =~ s/[^\/]+$/autounblock.inc/;
	require $fn;
} or die("shared auto unblock code not available\n");
print "ok 2\n";

sub checkAccess(@) {
	return(0);
}

$group = "Vendor:App"; $mode = "rw";
$id = Dazuko::IO::Register_TS($group, $mode);
print defined $id ? "" : "not ", "ok 3\n";

$mask = $DAZUKO_ON_OPEN | $DAZUKO_ON_CLOSE;
$rc = Dazuko::IO::SetAccessMask_TS($id, $mask);
print $rc == 0 ? "" : "not ", "ok 4\n";

$path = &get_abs_cwd();
print defined $path ? "" : "not ", "ok 5\n";
$rc = Dazuko::IO::AddIncludePath_TS($id, $path);
print $rc == 0 ? "" : "not ", "ok 6\n";

$path = "/proc";
$rc = Dazuko::IO::AddExcludePath_TS($id, $path);
print $rc == 0 ? "" : "not ", "ok 7\n";

&schedule_access($0)
	or print "not ";
print "ok 8\n";
@acc = Dazuko::IO::GetAccess_TS($id);
print @acc ? "" : "not ", "ok 9\n";

if (@acc) {
	( $ref, $deny, $event, $flags, $mode, $uid, $pid,
		$filename, $filesize, $fileuid, $filegid, $filemode,
		$filedevice, ) = @acc;
	$deny = &checkAccess(@acc);
	$rc = Dazuko::IO::ReturnAccess_TS($id, $ref, $deny);
	print $rc == 0 ? "" : "not ", "ok 10\n";
}

$rc = Dazuko::IO::Unregister_TS($id);
print $rc == 0 ? "" : "not ", "ok 11\n";

1;

# ----- E O F ---------------------------------------------------
