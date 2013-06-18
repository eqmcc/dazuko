#!/usr/bin/perl
# ----- t04.t ---------------------------------------------------
# vim:set syntax=perl:

# test for the Dazuko::Access module

use strict;

my $loaded = 0;

BEGIN { $| = 1; print "1..4\n"; }
use Dazuko::Access;
$loaded = 1;
print "ok 1\n";
END { print "not ok 1\n" unless $loaded; }

my ( $acc, );

$acc = Dazuko::Access->new();
print defined $acc ? "" : "not ", "ok 2\n";

$acc->deny(1);
print $acc->deny() == 1 ? "" : "not ", "ok 3\n";

$acc->deny(0);
print $acc->deny() == 0 ? "" : "not ", "ok 4\n";

$acc = undef;

1;

# ----- E O F ---------------------------------------------------
