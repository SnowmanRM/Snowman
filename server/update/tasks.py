import datetime
import logging
import mimetypes
import os
import time
import subprocess

from srm.settings import BASE_DIR
from update.models import Source, Update
import util.logger

class UpdateTasks:
	"""This class exposes the different method which we use for prcessing update-files."""

	@staticmethod
	def update(filename, sourcename = "Manual"):
		"""This method spawns a subprocess calling the script 'scripts/runUpdate.py', which
		is actually doing the update. (Or, actually, it is just calling UpdateTasks,runUpdate).
		If this method is called in its own process, we will accomplish process-separation, and
		the famous double-fork, so it should be able to run asynchronusly to the webserver."""
		logger = logging.getLogger(__name__)
		subprocess.call([os.path.join(BASE_DIR, 'scripts/runUpdate.py'), filename, sourcename])

	@staticmethod
	def runUpdate(filename, sourcename = "Manual"):
		"""This method is doing an update. It is identifying what kind of file we have, and 
		unpacks/parses it accordingly."""
		logger = logging.getLogger(__name__)
		
		logger.info("%d Starting update from %s with %s" % (os.getpid(), sourcename, filename))
		try:
			source = Source.objects.get(name=sourcename)
		except Source.DoesNotExist:
			logger.error("Could not find update-source with the name: %s. Update with PID:%d is therfore cancelled." % (sourcename, os.getpid()))
			return 1
		
		# If the appropriate source is found, we create an update-object, and starts working.
		update = Update.objects.create(source = source, time=datetime.datetime.now())

		filetype = mimetypes.guess_type(filename)
		if(filetype[0] == 'text/plain'):
			logger.debug("%d File is identified as plaintext" % os.getpid())
			update.parseConfigFile(filename)
		elif(filetype[0] == 'application/x-tar'):
			logger.debug("%d File is identified as a tar-archive" % os.getpid())
			#TODO: Unpack tar, and parse the files.
		#TODO: If filetype == folder, use erik's functions.. :)
		
		logger.info("%d Finished update from %s with %s" % (os.getpid(), sourcename, filename))
