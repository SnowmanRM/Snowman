#!/usr/bin/env python
"""
This script is used by the webpage, to do the parsing of the configuration-files asynchronusly,
so that the webpage does not need to block while processing data.

The script can also be invoked manually. It is able to process a single textfile, an archive 
(tar(gz), zip) or an unpacked folder.
"""

import logging
import os
import resource
import sys
from datetime import datetime

# Add the parent folder of the script to the path
scriptpath = os.path.realpath(__file__)
scriptdir = os.path.dirname(scriptpath)
parentdir = os.path.dirname(scriptdir)
sys.path.append(parentdir)

from util.tools import doubleFork
doubleFork()

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
	else:
		try:
			s = Source.objects.get(name=sourcename)
		except:
			logger.warning("Could not find a source for the manual update.")
			sys.exit(1)

	if(s.locked):
		logger.info("Could not update '%s', as there seems to already be an update going for this source." % s.name)
		sys.exit(1)
	else:
		s.locked = True
		s.save()
		logger.info("Starting the update from %s, with PID:%d." % (s.name, os.getpid()))
	
	# Start doing the update.
	try:
		UpdateTasks.runUpdate(filename, sourcename)
		logger.info("Finished the update, with PID:%d, from: %s" % (os.getpid(), filename))
	except:
		logger.warnign("Something happened while doing a manual update of %s", s.name)
	finally:
		s.locked = False
		s.save()
