#!/usr/bin/perl
# vim:set syntax=perl:

# simple test for successful registration and unregistration
# (i.e. don't block on GetAccess() etc)

######################### We start with some black magic to print on failure.

BEGIN { $| = 1; print "1..4\n"; }
END {print "not ok 1\n" unless $loaded;}
use Dazuko::IO;
$loaded = 1;
print "ok 1\n";

######################### End of black magic.

my $rc;

$rc = Dazuko::IO::Register("groupname", "r");
print $rc == 0 ? "" : "not ", "ok 2\n";

$rc = Dazuko::IO::SetAccessMask(3);
print $rc == 0 ? "" : "not ", "ok 3\n";

$rc = Dazuko::IO::Unregister();
print $rc == 0 ? "" : "not ", "ok 4\n";

1;

