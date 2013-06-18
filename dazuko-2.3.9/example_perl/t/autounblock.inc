#!/usr/bin/perl
# ----- autounblock.inc -----------------------------------------
# vim:set syntax=perl:

# help automatically unblock the CheckAccess() test cases:
# register abs(cwd) as include, access a file after a delay

my $unblock_delay = .3;

sub get_abs_cwd() {
	my ( $fn, );

	$fn = undef;
	# try it the portable way
	eval {
		use File::Spec;
		$fn = File::Spec->curdir();;
		$fn = File::Spec->rel2abs($fn);
	} or $fn = undef;
	# not every Perl installation has rel2abs()
	# try an external pwd command (works on UNIX)
	eval {
		# $fn = qx( pwd -P ); # causes /bin/pwd to issue warings
		$fn = qx( pwd );
		chomp $fn;
	} or $fn = undef;
	# we might have missed Windows here
	# what else to try?
	return(undef)
		unless ($fn);
	return(undef)
		unless (-d $fn);
	return($fn);
}

sub schedule_access($$) {
	my ( $fn, $delay, ) = @_;
	my ( $pid, @cont, );

	# start a background process
	$pid = fork();
	return(undef)
		unless (defined $pid);
	return(1)
		if ($pid != 0);

	# wait for a short while
	$delay = $unblock_delay
		unless (defined $delay);
	select(undef, undef, undef, $delay);

	# access the file, unblock GetAccess()
	open(F, "< $fn")
		or return(undef);
	@cont = <F>;
	close(F)
		or return(undef);

	# we're the child, terminate
	exit(0);
}

1;

# ----- E O F ---------------------------------------------------
