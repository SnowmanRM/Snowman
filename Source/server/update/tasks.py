import datetime
import logging
import mimetypes
import os
import tempfile
import shutil
import tarfile
import zipfile
import ConfigParser

from util.config import Config
from update.models import Source, Update, UpdateLog
from update.parser import Parser

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

		# Add our custom mimetypes:
		mimetypes.add_type('text/plain', '.rules')
		mimetypes.add_type('text/plain', '.conf')
		mimetypes.add_type('text/plain', '.config')
		mimetypes.add_type('text/plain', '.map')
		
		filetype = mimetypes.guess_type(filename)
		if(filetype[0] == 'text/plain'):
			logger.debug("%d File is identified as plaintext" % os.getpid())
			UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="10 Started to parse the file.")
			
			fileTuple = (filename, "")			
			update.parseConfigFile(fileTuple, storeHash=False)

		#elif(filetype[0] == 'application/x-tar'):
		elif(tarfile.is_tarfile(filename)):
			logger.debug("%d File is identified as a tar-archive" % os.getpid())

			# Create a temporary working-directory
			UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="9 Unpacking downloaded archive")
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
			UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="9 Unpacking downloaded archive")
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
			
		parser = Parser(update)
			
		if sourceName == "Manual":
			storeHash = False
		else:
			storeHash = True
		
		if Config.get("files", "useFileNames") == "true":
			# Filenames to look for:
			ruleFiles = []
			
			classificationFilename = "classificationFile"
			genMsgFilename = "genMsgFile"
			referenceConfigFilename = "referenceConfigFile"
			sidMsgFilename = "sidMsgFile"
			filterFilename = "filterFile"
			ruleExt = "ruleExt"
			
			configFiles = {}
			for filename in [classificationFilename,genMsgFilename,referenceConfigFilename,sidMsgFilename,filterFilename,ruleExt]:
				try:
					configFiles[filename] = Config.get("files", filename)
				except ConfigParser.NoOptionError:
					configFiles[filename] = ""
					logger.warning("A configuration string for option '"+filename+"' in section 'files' was not found.")

			# Place to mark if we found the files
			foundClassifications = False
			foundGenMsg = False
			foundReferences = False
			foundSidMsg = False
			foundFilter = False
			
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
					
					if updateFile.endswith(configFiles[ruleExt]):
						ruleFiles.append(fileTuple)
						noFiles += 1
					elif updateFile == configFiles[classificationFilename]:
						foundClassifications = True
						classificationFile = fileTuple
						noFiles += 1
					elif updateFile == configFiles[genMsgFilename]:
						foundGenMsg = True
						genMsgFile = fileTuple
						noFiles += 1
					elif updateFile == configFiles[referenceConfigFilename]:
						foundReferences = True
						referenceConfigFile = fileTuple
						noFiles += 1
					elif updateFile == configFiles[sidMsgFilename]:
						foundSidMsg = True
						sidMsgFile = fileTuple
						noFiles += 1
					elif updateFile == configFiles[filterFilename]:
						foundFilter = True
						filterFile = fileTuple
						noFiles += 1
			
			UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="13 Found %d files to parse" % noFiles)
			
			# Update must parse files in the following order:
			# 1. Read and update the classifications
			# 2. Read and update the generators
			# 3. Read and update the reference types
			# 4. Read and update the rules
			# 5. Read and update the rule messages (which includes references)	
			
			if(foundClassifications):
				UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="15 Parsing %s" % classificationFile[1])
				parser.parseClassificationFile(classificationFile)
			if(foundGenMsg):
				UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="17 Parsing %s" % genMsgFile[1])
				parser.parseGenMsgFile(genMsgFile)
			if(foundReferences):
				UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="19 Parsing %s" % referenceConfigFile[1])
				parser.parseReferenceConfigFile(referenceConfigFile)
			
			current = 20
			step = float(50) / float(len(ruleFiles))
			for updateFile in ruleFiles:
				UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="%d Parsing %s" % (int(current), updateFile[1]))
				parser.parseRuleFile(updateFile)
				current = current + step

			if foundSidMsg:		
				UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="70 Parsing %s" % sidMsgFile[1])
				parser.parseSidMsgFile(sidMsgFile)
				
			if foundFilter:
				UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="75 Parsing %s" % filterFile[1])
				parser.parseFilterFile(filterFile)

		else:
			
			skipGroup = []
			try:
				extensions = Config.get("files", "skipExt")
				skipGroup = extensions.split(", ")
			except ConfigParser.NoOptionError:
				pass
				
			# Walk through the directory structure and extract the absolute path
			# of all interesting files:
			files = []
			noFiles = 0
			UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="12 Collecting files")
			for dirpath, dirnames, filenames in os.walk(path):
				for updateFile in filenames:
					if os.path.splitext(updateFile)[1] not in skipGroup:
						# Create a tuple with (absolute filepath, root folder path)
						# This will be used to store relative paths in the DB
						absoluteFilePath = os.path.join(dirpath, updateFile)
						relativeFilePath = os.path.relpath(absoluteFilePath, path) 
						fileTuple = (absoluteFilePath, relativeFilePath)
						files.append(fileTuple)
						noFiles += 1
			
			UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="13 Found %d files to parse" % noFiles)			

			current = 20
			step = float(55) / float(len(files))
			for updateFile in files:
				UpdateLog.objects.create(update=update, time=datetime.datetime.now(), logType=UpdateLog.PROGRESS, text="%d Parsing %s" % (int(current), updateFile[1]))
				parser.parseConfigFile(updateFile, storeHash)
				current = current + step

		parser.save()		
		logger.info("Finished processing the update-folder: %s" % path)
