import datetime
import logging
import mimetypes
import os
import tempfile
import shutil
import tarfile
import zipfile

from update.models import Source, Update, UpdateLog

class UpdateTasks:
	"""This class exposes the different method which we use for processing update-files."""

	@staticmethod
	def runUpdate(filename, sourcename = "Manual", update = None):
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
		if(update == None):
			update = Update.objects.create(source = source, time=datetime.datetime.now())
			source = update.source

		filetype = mimetypes.guess_type(filename)
		if(filetype[0] == 'text/plain'):
			logger.debug("%d File is identified as plaintext" % os.getpid())
			UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="10 Started to parse the file.")
			update.parseConfigFile(filename)

		#elif(filetype[0] == 'application/x-tar'):
		elif(tarfile.is_tarfile(filename)):
			logger.debug("%d File is identified as a tar-archive" % os.getpid())

			# Create a temporary working-directory
			UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="1 Unpacking downloaded archive")
			tmpdirectory = tempfile.mkdtemp()

			# Unpack the archive
			try:
				tar = tarfile.open(filename, "r")
				tar.extractall(tmpdirectory)
			except tarfile.CompressionError:
				logger.error("%d Could not recognize the compression used in tarfile '%s'. Update is therefore not performed." % (os.getpid(), filename))
			else:
				# Process the content
				UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="10 Starting to parse the archive")
				UpdateTasks.processFolder(tmpdirectory, source.name, update=update)
	
				# Delete the temporary folder
				UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="98 Cleaning up.")
				shutil.rmtree(tmpdirectory)

		elif(filetype[0] == 'application/zip'):
			logger.debug("%d File is identified as a zip-archive" % os.getpid())

			# Create a temporary working-directory
			UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="1 Unpacking downloaded archive")
			tmpdirectory = tempfile.mkdtemp()

			# Unpack the archive
			logger.debug("%d Archive is unpacked to %s" % (os.getpid(), tmpdirectory))
			with zipfile.ZipFile(filename, "r") as z:
				z.extractall(tmpdirectory)

			# Process the content
			UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="10 Starting to parse the archive")
			UpdateTasks.processFolder(tmpdirectory, source.name, update=update)

			# Delete the temporary folder
			UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="98 Cleaning up.")
			shutil.rmtree(tmpdirectory)

		elif(os.path.isdir(filename)):		
			UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="10 Starting to parse the folder")
			logger.debug("%d File is identified as a folder" % os.getpid())
			UpdateTasks.processFolder(filename, source.name, update=update)
		
		UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="100 Finished the update.")
		logger.info("%d Finished update from %s with %s" % (os.getpid(), sourcename, filename))

	@staticmethod
	def processFolder(path, sourceName = "Manual", update = None):
		logger = logging.getLogger(__name__)
		logger.info("Starting to process an update-folder: %s" % path)
	
		# We do not catch the exception here, as the caller should be responsible to decide what to
		#   do if the source do not exist.
		source = Source.objects.get(name=sourceName)
		if(update == None):
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
		noFiles = 0
		UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="12 Collecting files")
		for dirpath, dirnames, filenames in os.walk(path):
			for updateFile in filenames:
				# Create a tuple with (absolute filepath, root folder path)
				# This will be used to store relative paths in the DB
				absoluteFilePath = os.path.join(dirpath, updateFile)
				relativeFilePath = os.path.relpath(absoluteFilePath, path) 
				fileTuple = (absoluteFilePath, relativeFilePath)
				
				if updateFile.endswith(".rules"):
					ruleFiles.append(fileTuple)
					noFiles += 1
				elif updateFile == classificationFile:
					foundClassifications = True
					classificationFile = fileTuple
					noFiles += 1
				elif updateFile == genMsgFile:
					foundGenMsg = True
					genMsgFile = fileTuple
					noFiles += 1
				elif updateFile == referenceConfigFile:
					foundReferences = True
					referenceConfigFile = fileTuple
					noFiles += 1
				elif updateFile == sidMsgFile:
					sidMsgFile = fileTuple
					noFiles += 1
		
		UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="13 Found %d files to parse" % noFiles)
		
		# Update must parse files in the following order:
		# 1. Read and update the classifications
		# 2. Read and update the generators
		# 3. Read and update the reference types
		# 4. Read and update the rules
		# 5. Read and update the rule messages (which includes references)
		
		# Cache objects across files to save time:
		rulesets = {}
		ruleclasses = {}
		generators = {}		
		
		if(foundClassifications):
			UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="15 Parsing %s" % classificationFile[1])
			update.parseClassificationFile(classificationFile, ruleclasses=ruleclasses)
		if(foundGenMsg):
			UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="17 Parsing %s" % genMsgFile[1])
			update.parseGenMsgFile(genMsgFile, generators=generators)
		if(foundReferences):
			UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="19 Parsing %s" % referenceConfigFile[1])
			update.parseReferenceConfigFile(referenceConfigFile)
		
		current = 20
		step = float(50) / float(len(ruleFiles))
		for updateFile in ruleFiles:
			UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="%d Parsing %s" % (int(current), updateFile[1]))
			update.parseRuleFile(updateFile, rulesets=rulesets, ruleclasses=ruleclasses, generators=generators)
			current = current + step
	
		UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="70 Parsing %s" % sidMsgFile[1])
		update.parseSidMsgFile(sidMsgFile)
		
		logger.info("Finished processing the update-folder: %s" % path)
