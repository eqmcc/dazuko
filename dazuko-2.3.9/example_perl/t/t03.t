#!/usr/bin/perl
# ----- t03.t ---------------------------------------------------
# vim:set syntax=perl:

# test for the whole Dazuko::Obj interface

use strict;

my $loaded = 0;

BEGIN { $| = 1; print "1..13\n"; }
use Dazuko::Obj;
$loaded = 1;
print "ok 1\n";
END { print "not ok 1\n" unless $loaded; }

eval {
	my $fn;
	$fn = $0;
	$fn =~ s/[^\/]+$/autounblock.inc/;
	require $fn;
} or die("shared auto unblock code not available\n");
print "ok 2\n";

my ( $dazuko, $rc, $group, $mode, $mask, $path, );

$dazuko = Dazuko::Obj->new();
print defined $dazuko ? "" : "not ", "ok 3\n";

$group = "Vendor:App"; $mode = "rw";
$rc = $dazuko->Register($group, $mode);
print $rc ? "" : "not ", "ok 4\n";

$mask = $Dazuko::IO::DAZUKO_ON_OPEN | $Dazuko::IO::DAZUKO_ON_CLOSE;
$rc = $dazuko->AccessMask($mask);
print $rc ? "" : "not ", "ok 5\n";

$path = &get_abs_cwd();
print defined $path ? "" : "not ", "ok 6\n";
$rc = $dazuko->Include($path);
print $rc ? "" : "not ", "ok 7\n";

$rc = $dazuko->Exclude(qw( /dev/null /proc ));
print $rc ? "" : "not ", "ok 8\n";

&schedule_access($0)
	or print "not ";
print "ok 9\n";

$rc = $dazuko->GetAccess();
print $rc ? "" : "not ", "ok 10\n";

$dazuko->CheckAccess();
print "ok 11\n";

$rc = $dazuko->ReturnAccess();
print $rc ? "" : "not ", "ok 12\n";

$rc = $dazuko->Unregister();
print $rc ? "" : "not ", "ok 13\n";

$dazuko = undef;

1;

# ----- E O F ---------------------------------------------------
