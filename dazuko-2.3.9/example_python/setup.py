# ----- setup.py ------------------------------------------------
# distutils "makefile" for the dazuko python binding

from distutils.core import setup, Extension

module1 = Extension(
	'dazuko',
	define_macros = [
		('MAJOR_VERSION', '0'),
		('MINOR_VERSION', '2'),
	],
	include_dirs = [
		'..',
		'/usr/local/include',
	],
	libraries = [
		'dazuko',
	],
	library_dirs = [
		'../library',
	],
	sources = [
		'dazukomodule.c',
	],
)

setup (
	name = 'PyDazuko',
	version = '0.2',
	description = 'Python binding for Dazuko',
	author = 'Gerhard Sittig',
	author_email = 'gsittig@antivir.de',
	url = 'http://www.dazuko.org/',
	license = 'BSD',
# 	platform = [ 'FreeBSD', 'Linux' ],
	long_description = '''
Dazuko is a means to hook into a machine's file system and can be used
to monitor (log for diagnostic purposes) or intercept (filter based on
scan results) access to data (files and directories).  Dazuko is mostly
used by antivirus scanners to achieve on access scan capabilites.

See http://www.dazuko.org/ for additional information.
			    
This module provides a Python interface to Dazuko.
''',
	ext_modules = [ module1, ],
)

# ----- E O F ---------------------------------------------------
