#!/usr/bin/env python
"""
This script is used by the webpage, to do the parsing of the configuration-files asynchronusly,
so that the webpage does not need to block while processing data.

The script can also be invoked manually. It should (when finished) be able to process a single
textfile, an archive (tar(gz), zip) or an unpacked folder.
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
	# Init the logger TODO: Why do we get the logger from the parent process?
	#util.logger.initialize()
	logger = logging.getLogger(__name__)
	
	# Grab the parametres.
	try:
		filename = sys.argv[1]
	except IndexError:
		print "Usage: %s <update directory> [source]"
		sys.exit(1)
		
	try:
		sourcename = sys.argv[2]
	except IndexError:
		sourcename = "Manual"

	# Start doing the update.
	logger.info("Starting run-update-script")
	UpdateTasks.runUpdate(filename, sourcename)
	logger.info("Finishing run-update-script")
