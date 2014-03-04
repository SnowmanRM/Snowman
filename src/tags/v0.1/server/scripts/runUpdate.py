#!/usr/bin/env python
"""
This script is used by the webpage, to do the parsing of the configuration-files asynchronusly,
so that the webpage does not need to block while processing data.

The script can also be invoked manually. It is able to process a single textfile, an archive 
(tar(gz), zip) or an unpacked folder.
"""

import logging
import os
import sys
from datetime import datetime

# Add the parent folder of the script to the path
scriptpath = os.path.realpath(__file__)
scriptdir = os.path.dirname(scriptpath)
parentdir = os.path.dirname(scriptdir)
sys.path.append(parentdir)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "srm.settings")

from update.models import Update, Source
from update.tasks import UpdateTasks
import util.logger

if __name__ == "__main__":
	logger = logging.getLogger(__name__)
	
	# Grab the parametres.
	try:
		filename = sys.argv[1]
	except IndexError:
		print "Usage: %s <update directory> [<source>] [create]"
		sys.exit(1)
		
	try:
		sourcename = sys.argv[2]
	except IndexError:
		sourcename = "Manual"

	logger.info("Starting the update, with PID:%d, from: %s" % (os.getpid(), filename))
	# Creating the source if desired and needed.
	if("create" in sys.argv):
		s, c = Source.objects.get_or_create(name=sourcename)
		if(c):
			logger.info("Created a new source during updates: %s", s)

	# Start doing the update.
	UpdateTasks.runUpdate(filename, sourcename)
	logger.info("Finished the update, with PID:%d, from: %s" % (os.getpid(), filename))
