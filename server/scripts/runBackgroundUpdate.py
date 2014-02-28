#!/usr/bin/env python
"""
"""

import hashlib
import logging
import os
import resource
import sys
import traceback
import urllib2
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
from util.config import Config
import util.logger

logger = logging.getLogger(__name__)

if __name__ == "__main__":
	logger = logging.getLogger(__name__)
	
	# Grab the parametres.
	try:
		sourceID = int(sys.argv[1])
	except IndexError:
		print "Usage: %s <source_id>"
		sys.exit(1)

	try:
		source = Source.objects.get(pk=sourceID)
	except Source.DoesNotExist:
		logger.error("Could not find source with ID:%d" % sourceID)
		sys.exit(1)

	logger.info("Starting the update from %s, with PID:%d." % (source.name, os.getpid()))
	
	if(len(source.md5url) > 0):
		try:
			socket = urllib2.urlopen(source.md5url)
			md5 = socket.read()
			md5 = md5.strip()
			socket.close()

			logger.debug("Downloaded-MD5:'%s'" % str(md5))
			logger.debug("LastUpdate-MD5:'%s'" % str(source.lastMd5))
		except:
			logger.warning("Could not find the md5-file at %s. Proceeding to download the main update-file." % source.md5url)
			md5 = ""
	else:
		logger.info("No md5-url file found. Proceeding to download the main update-file.")
		md5 = ""
	
	
	if(len(str(md5)) == 0 or str(md5) != str(source.lastMd5)):
		logger.info("Starting to download %s" % source.url)
		storagelocation = Config.get("storage", "inputFiles")		
		filename = storagelocation + source.url.split("/")[-1]
		
		if(os.path.isdir(storagelocation) == False):
			os.makedirs(storagelocation)

		try:
			socket = urllib2.urlopen(source.url)
	
			f = open(filename, "w")
			_hash = hashlib.md5()
			blocksize = 65536
			while True:
				buffer = socket.read(blocksize)
				if not buffer:
					socket.close()
					f.close()
					break
				f.write(buffer)
				_hash.update(buffer)

		except urllib2.HTTPError as e:
			logger.error("Error during download: %s" % str(e))
			sys.exit(1)

		logger.debug("Downloaded-MD5:'%s'" % str(_hash.hexdigest()))
		logger.debug("LastUpdate-MD5:'%s'" % str(source.lastMd5))
	
		if(str(_hash.hexdigest()) != str(source.lastMd5)):
			logger.info("Processing the download" )
			try:
				UpdateTasks.runUpdate(filename, source.name)
			except Exception as e:
				logger.critical("Hit exception while running update: %s" % str(e))
				logger.debug("%s" % (traceback.format_exc()))
				sys.exit(1)
		
			logger.info("Storing md5 of this update: %s" % (_hash.hexdigest()))
			source.lastMd5 = _hash.hexdigest()
			source.save()
		else:
			logger.info("The downloaded file has the same md5sum as the last file we updated from. Skipping update.")
	else:
		logger.info("We already have the latest version of the %s ruleset. Skipping download." % source.name)

	logger.info("Finished the update, with PID:%d, from: %s" % (os.getpid(), source.name))
