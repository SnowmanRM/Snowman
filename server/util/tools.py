"""This module is intended for non-django tools, that we might use here and there."""

import os
import resource
import sys
import hashlib

def md5sum(filename, blocksize=65536):
	"""Returns the md5 sum of the file specified.
	Reading blocksize can be customized."""
	
	_hash = hashlib.md5()
	with open(filename, "r+b") as f:
		for block in iter(lambda: f.read(blocksize), ""):
			_hash.update(block)
	return _hash.hexdigest()

def doubleFork():
	"""This method does a double fork, and kills both parents. So, after this method is returned,
	you are guaranteed to be in a free-standing process, if no exceptions was raised.
	
	WARNING: As this method kills the parent process, you would probably not want to call this
				as a method from the webserver."""

	# First fork
	pid = os.fork()

	# If I now am first child:
	if pid == 0:
		# Set the child to be its own session-leader.
		os.setsid()
	
		# Fork the second time
		pid = os.fork()
		
		# If new child
		if pid == 0:
			os.chdir("/")
			os.umask(0)
		
		# If parent, die.
		else:
			sys.exit()

	# If parent, die
	else:
		sys.exit()
	
	# Determine how many filedescriptors that might be present.
	maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
	if (maxfd == resource.RLIM_INFINITY):
		maxfd = MAXFD
	
	# Iterate through and close all file descriptors.
	for fd in range(0, maxfd):
		try:
			os.close(fd)
		except OSError:	# ERROR, fd wasn't open to begin with (ignored)
			pass
	
	# Open a df to /dev/null
	os.open('/dev/null', os.O_RDWR)	# standard input (0)
	
	# Duplicate standard input to standard output and standard error.
	os.dup2(0, 1)			# standard output (1)
	os.dup2(0, 2)			# standard error (2)
