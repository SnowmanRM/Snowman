import datetime
import logging
import mimetypes
import os
import sys
import time
import tempfile
import shutil
import subprocess
import tarfile
import zipfile

from srm.settings import BASE_DIR
from update.models import Source, Update
import util.logger

class UpdateTasks:
	"""This class exposes the different method which we use for processing update-files."""

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

		#elif(filetype[0] == 'application/x-tar'):
		elif(tarfile.is_tarfile(filename)):
			logger.debug("%d File is identified as a tar-archive" % os.getpid())
			# Create a temporary working-directory
			tmpdirectory = tempfile.mkdtemp()

			# Unpack the archive
			try:
				tar = tarfile.open(filename, "r")
				tar.extractall(tmpdirectory)
			except CompressionError:
				logger.error("%d Could not recognize the compression used in tarfile '%s'. Update is therefore not performed." % (os.getpid(), filename))
			else:
				# Process the content
				UpdateTasks.processFolder(tmpdirectory, source.name)
	
				# Delete the temporary folder
				shutil.rmtree(tmpdirectory)

		elif(filetype[0] == 'application/zip'):
			logger.debug("%d File is identified as a zip-archive" % os.getpid())

			# Create a temporary working-directory
			tmpdirectory = tempfile.mkdtemp()

			# Unpack the archive
			logger.debug("%d Archive is unpacked to %s" % (os.getpid(), tmpdirectory))
			with zipfile.ZipFile(filename, "r") as z:
				z.extractall(tmpdirectory)

			# Process the content
			UpdateTasks.processFolder(tmpdirectory, source.name)

			# Delete the temporary folder
			shutil.rmtree(tmpdirectory)

		elif(os.path.isdir(filename)):		
			logger.debug("%d File is identified as a folder" % os.getpid())
			UpdateTasks.processFolder(filename, source.name)
		
		logger.info("%d Finished update from %s with %s" % (os.getpid(), sourcename, filename))

	@staticmethod
	def processFolder(path, sourceName = "Manual"):
		logger = logging.getLogger(__name__)
		logger.info("Starting to process an update-folder: %s" % path)
	
		# We do not catch the exception here, as the caller should be responsible to decide what to
		#   do if the source do not exist.
		source = Source.objects.get(name=sourceName)
		
		update = Update.objects.create(time=datetime.datetime.now(), source=source)
		
		# Filenames to look for:
		ruleFiles = []
		classificationFile = "classification.config"
		genMsgFile = "gen-msg.map"
		referenceConfigFile = "reference.config"
		sidMsgFile = "sid-msg.map"
		
		# Place to mark if we found the files
		foundClassifications = False
		foundGenMsg = False
		foundReferences = False
		
		# Walk through the directory structure and extract the absolute path
		# of all interesting files:
		for dirpath, dirnames, filenames in os.walk(path):
			for ruleFile in filenames:
				if ruleFile.endswith(".rules"):
					# Save the absolute path of the rule file
					ruleFiles.append(os.path.join(dirpath, ruleFile))
				elif ruleFile == classificationFile:
					foundClassifications = True
					classificationFile = os.path.join(dirpath, ruleFile)
				elif ruleFile == genMsgFile:
					foundGenMsg = True
					genMsgFile = os.path.join(dirpath, ruleFile)
				elif ruleFile == referenceConfigFile:
					foundReferences = True
					referenceConfigFile = os.path.join(dirpath, ruleFile)
				elif ruleFile == sidMsgFile:
					sidMsgFile = os.path.join(dirpath, ruleFile)
		
		
		# Update must parse files in the following order:
		# 1. Read and update the classifications
		# 2. Read and update the generators
		# 3. Read and update the reference types
		# 4. Read and update the rules
		# 5. Read and update the rule messages (which includes references)
		
		if(foundClassifications):
			update.parseClassificationFile(classificationFile)
		if(foundGenMsg):
			update.parseGenMsgFile(genMsgFile)
		if(foundReferences):
	   		update.parseReferenceConfig(referenceConfigFile)
		
		for ruleFile in ruleFiles:
			update.parseRuleFile(ruleFile)
	
		update.parseSidMsgFile(sidMsgFile)
		
		logger.info("Finished processing the update-folder: %s" % path)
