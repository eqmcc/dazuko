# ----- Makefile.PL ---------------------------------------------
# creates a Makefile for the Dazuko perlxs(1) wrapper

use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME'	=> 'Dazuko::IO',
    'VERSION_FROM' => 'IO.pm',
    'LIBS'	=> ['-L../library -ldazuko'],
    'DEFINE'	=> '',
    'INC'	=> '-I..', # should be -I../library
);

# ----- E O F ---------------------------------------------------
