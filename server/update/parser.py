import re, logging
from os import path
from update.models import UpdateFile
from update.exceptions import AbnormalRuleError, BadFormatError
from util.tools import md5sum, Replace
from util.patterns import ConfigPatterns
from updater import Updater

class Parser:
	def __init__(self, update):
		self.update = update
		self.updater = Updater()
	
	def parseRuleFile(self, paths):
		"""Method to initiate parsing of a rule file.
		parseFile returns a method which feeds the file line by line
		to the updateRule method.
		
		paths argument contains a tuple with absolute and relative file path."""
		
		# Get the absolute file path
		filename = path.basename(paths[0])
		self.parseFile(self.updateRule, paths, filename=filename)()

	def parseClassificationFile(self, paths):
		"""Method to initiate parsing of a classifications file.
		parseFile returns a method which feeds the file line by line
		to the updateClassification method.
		
		paths argument contains a tuple with absolute and relative file path."""
		
		self.parseFile(self.updateClassification, paths)()
		
	def parseGenMsgFile(self, paths):
		"""Method to initiate parsing of a gen-msg file.
		parseFile returns a method which feeds the file line by line
		to the updateGenMsg method.
		
		paths argument contains a tuple with absolute and relative file path."""
			
		self.parseFile(self.updateGenMsg, paths)()
		
	def parseReferenceConfigFile(self, paths):
		"""Method to initiate parsing of a reference config file.
		parseFile returns a method which feeds the file line by line
		to the updateReferenceConfig method.
		
		paths argument contains a tuple with absolute and relative file path."""
		
		self.parseFile(self.updateReferenceConfig, paths)()
		
	def parseSidMsgFile(self, paths):
		"""Method to initiate parsing of a sid-msg file.
		parseFile returns a method which feeds the file line by line
		to the updateSidMsg method.
		
		paths argument contains a tuple with absolute and relative file path."""
				
		self.parseFile(self.updateSidMsg, paths)()		

			
	def parseFilterFile(self, paths):
		"""Method to initiate parsing of a threshold.conf/event_filter file.
		parseFile returns a method which feeds the file line by line
		to the updateFilter method.
		
		paths argument contains a tuple with absolute and relative file path."""

		self.parseFile(self.updateFilter, paths)()
		
	def parseConfigFile(self, path, storeHash=True, **kwargs):
		"""Method to parse an ASCII file with undefined content.
		Each line of file is sent to updateConfig, which tries to identify
		the content by matching the line to regex patterns defined in patterns-list."""
		
		# Compile the re-patterns
		patterns = {}
		patterns['rule'] = re.compile(ConfigPatterns.RULE)
		patterns['reference'] = re.compile(ConfigPatterns.REFERENCE)
		patterns['class'] = re.compile(ConfigPatterns.CLASS)
		patterns['genmsg'] = re.compile(ConfigPatterns.GENMSG)
		patterns['sidmsg'] = re.compile(ConfigPatterns.SIDMSG)
		patterns['filter'] = re.compile(ConfigPatterns.EVENT_FILTER)
		
		filename = path.basename(path[0])
		self.parseFile(self.updateConfig, path, storeHash, filename=filename, patterns=patterns, **kwargs)()		
			
	def updateRule(self, raw, filename):
		"""This method takes a raw rulestring, parses it, and sends each valid rule to the updater."""
		
		logger = logging.getLogger(__name__)
		
		try:
			# Snowman is currently only handling rules with GID=1.
			# If we find a GID element with a value other than 1, we are parsing the wrong file.
			ruleGID = int(re.match(ConfigPatterns.GID, raw).group(1))
			if ruleGID != 1:
				raise AbnormalRuleError
		except AttributeError:
			# If no GID element is found, GID is 1.
			ruleGID = 1
		except ValueError:
			raise BadFormatError("Bad rule in file '"+filename+"': GID is not numeric! Rulestring: "+raw)
		
		# Construct a regex to match all elements a raw rulestring 
		# must have in order to be considered a valid rule
		# (sid, rev, message and classtype):
		matchPattern = ConfigPatterns.RULE
		pattern = re.compile(matchPattern)
		
		# Match optional options:
		ruleset = re.match(ConfigPatterns.RULESET, raw)
		priority = re.match(ConfigPatterns.PRIORITY, raw)
		references = re.findall(ConfigPatterns.RULEREFERENCE, raw)
		eventFilter = re.match(ConfigPatterns.THRESHOLD, raw)
		detectionFilter = re.match(ConfigPatterns.DETECTION_FILTER, raw)
				
		# If the raw rule matched the regex: 
		result = pattern.match(raw)
		if(result):
			
			# Assign some helpful variable-names:
			if("#" in result.group(1)):
				raw = raw.lstrip("# ")
				ruleActive = False
			else:
				ruleActive = True
			
			try:	
				ruleSID = int(result.group(2))
				ruleRev = int(result.group(3))
			except ValueError:
				raise BadFormatError("Bad rule in '"+filename+"': SID or rev is not numeric! Rulestring: "+raw)
						
			ruleMessage = result.group(4)
			ruleClassName = result.group(5)
				
			# Ruleset name set to filename if not found in raw string:
			try:
				rulesetName = ruleset.group(1)
			except AttributeError:
				rulesetName = re.sub('\.rules$', '', filename)
				
			if priority:
				try:
					rulePriority = int(priority.group(0))
				except ValueError:
					raise BadFormatError("Bad rule in '"+filename+"': priority is not numeric! Rulestring: "+raw)
			else:
				rulePriority = None
				
			# Remove filters from raw string before storage:
			replace = Replace("")			
			filters = ""
			
			raw = re.sub(r'detection_filter:.*?;', replace, raw)
			filters += replace.matched or ""
			raw = re.sub(r'threshold:.*?;', replace, raw)
			filters += replace.matched or ""
			
			raw = " ".join(raw.split())			
				
			self.updater.addRule(ruleSID, ruleRev, raw, ruleMessage, ruleActive, rulesetName, ruleClassName, rulePriority, ruleGID)	

			if detectionFilter:
				dfTrack = detectionFilter.group(1)
				dfCount = detectionFilter.group(2)
				dfSeconds = detectionFilter.group(3)
				self.checkFilter(ruleGID, ruleSID, dfTrack, dfCount, dfSeconds)
				self.updater.addFilter(ruleSID, dfTrack, dfCount, dfSeconds)

			if eventFilter:
				efType = eventFilter.group(1)
				efTrack = eventFilter.group(2)
				efCount = eventFilter.group(3)
				efSeconds = eventFilter.group(4)
				self.checkFilter(ruleGID, ruleSID, efTrack, efCount, efSeconds, efType)
				self.updater.addFilter(ruleSID, efTrack, efCount, efSeconds, efType)
				
			if references:
				for reference in references:
					try:
						referenceTypeName = reference[0]
						referenceData = reference[1]
						self.updater.addReference(referenceTypeName, referenceData, ruleSID)
					except IndexError:
						logger.warning("Skipping badly formatted reference for rule sid="+ruleSID+" in file '"+filename+"': "+str(reference))
							
	def updateClassification(self, raw):
		"""Method for parsing classification strings.
		Classification data consists of three comma-separated strings which are
		extracted with a regex, and split up in the three respective parts:
		classtype, description and priority. When a classification is deemed
		valid, it is sent to the updater."""
		
		# Regex: Match "config classification: " (group 0),
		# and everything that comes after (group 1), which is the classification data.
		result = re.match(ConfigPatterns.CLASS, raw)
		
		if result:
			# Split the data and store as separate strings
			classification = result.group(1).split(",")
			
			try:
				classtype = classification[0]
				description = classification[1]
				priority = int(classification[2])
			except (IndexError, ValueError):
				# If one or more indexes are invalid, the classification is badly formatted
				raise BadFormatError("Badly formatted rule classification: "+raw)
			
			self.updater.addClass(classtype, description, priority)

	def updateGenMsg(self, raw):
		"""Method for parsing generator strings.
		Generator data consists of two numbers and a message string, all three
		separated with a ||. All lines conforming to this pattern are split up
		in the three respective parts: GID (generatorID), alertID and message.
		Valid generators are sent to updater."""
				
		# Regex: Match a generator definition: int || int || string
		# If the line matches, it is stored in group(0)
		result = re.match(ConfigPatterns.GENMSG, raw)
		
		if result:
			# Split the line into GID, alertID and message
			# (becomes generator[0], [1] and [2] respectively)
			generator = result.group(0).split(" || ")

			try:					
				gid = int(generator[0])
				alertID = int(generator[1])
				message = generator[2]
				self.updater.addGenerator(gid, alertID, message)
			except (ValueError, IndexError):
				# If one or more indexes are invalid, or gid/alertID is not
				# numeric,  the generator is badly formatted
				raise BadFormatError("Badly formatted generator: "+raw)
		
	def updateReferenceConfig(self, raw):
		"""Method for parsing reference type strings, containing type name and
		url-prefix. Valid reference types are sent to updater."""		
		
		result = re.match(ConfigPatterns.REFERENCE, raw)
		
		if result:
			referenceType = result.group(1).strip()
			urlPrefix = result.group(2).strip()
			
			self.updater.addReferenceType(referenceType, urlPrefix)				
		
	def updateSidMsg(self, raw):
		"""The sid-msg.map file contains mappings between ruleSIDs, rule messages and ruleReferences.
		This method parses one line of this file (raw), and checks if the SID corresponds to a ruleRevision
		in this update. If this is the case, it updates the message in the ruleRevision and creates all ruleReferences.
		
		updatedRules is a dictionary with {SID:referenceID} entries. This is needed because rules are referenced
		by SID in sid-msg.map and by revisionID in Update.ruleRevisions."""
		
		# Regex: Match a generator definition: SID || message (|| reference)*
		# SID is stored in group(1), and "message (|| reference)*" in group(2)
		result = re.match(ConfigPatterns.SIDMSG, raw)
		
		# If we have a match AND the SID is in updatedRules (rule was updated):
		if result:
			
			try:
				# We have a valid line, fetch the SID
				ruleSID = int(result.group(1))
			except ValueError:
				raise BadFormatError("Expected numeric SID.")

			# Get message and ruleReferences, if any
			data = result.group(2).split(" || ")				
			dataiter = iter(data)			
			
			try:	
				# Rule message is always the first element
				message = next(dataiter)
				self.updater.addMessage(ruleSID, message)
				
				# Any succeeding elements are ruleReferences, formatted
				# with referenceType,referenceValue:
				for reference in dataiter:
					referenceData = reference.split(",")
					referenceType = referenceData[0]
					referenceValue = referenceData[1]
					self.updater.addReference(referenceType, referenceValue, ruleSID)
					
			except (StopIteration, IndexError):
				raise BadFormatError("Badly formatted sid-msg: "+raw)
			
	def updateFilter(self, raw):
		eventFilter = re.match(ConfigPatterns.EVENT_FILTER, raw)
		
		if eventFilter:
			efGID = eventFilter.group(1)
			efSID = eventFilter.group(2)
			efType = eventFilter.group(3)
			efTrack = eventFilter.group(4)
			efCount = eventFilter.group(5)
			efSeconds = eventFilter.group(6)
			self.checkFilter(efGID, efSID, efTrack, efCount, efSeconds, efType)
			self.updater.addFilter(int(efSID), efTrack, int(efCount), int(efSeconds), efType)
		else:
			suppress = re.match(ConfigPatterns.SUPPRESS, raw)
			
			if suppress:
				supGID = suppress.group(1)
				supSID = suppress.group(2)
				supTrack = suppress.group(3)
				supIP = suppress.group(4)
				
				if supTrack != "" and supIP != "":
					if supTrack not in ["by_src", "by_dst"]:
						raise BadFormatError("Bad suppress: "+raw)
					
					supIP = supIP.lstrip("[")
					supIP = supIP.rstrip("]")
					supIP = supIP.split(",")
					
					for address in supIP:
						if not re.match(ConfigPatterns.VALIDIPMASK, address):
							raise BadFormatError("Bad IP address in suppress: "+raw)
					
					self.updater.addSuppress(supSID, supTrack, supIP)
				else:
					self.updater.addSuppress(supSID)
			
	def parseFile(self, fn, filePathTuple, storeHash=True, **kwargs):
		def parse():
			"""Method for simple parsing of a file defined by filePathTuple. 
			Every line is sent to the function defined by fn."""
			
			absoluteFilepath, relativeFilePath = filePathTuple
			
			logger = logging.getLogger(__name__)
			logger.info("Parsing file "+absoluteFilepath+".")

			if storeHash:
				try:
					ruleFile = self.update.source.files.get(name=relativeFilePath)
				except UpdateFile.DoesNotExist:
					ruleFile = self.update.source.files.create(name=relativeFilePath, isParsed=False)
				oldHash = ruleFile.checksum
				newHash = md5sum(absoluteFilepath)
	
			if not storeHash or (oldHash != newHash):
				try:
					infile = open(absoluteFilepath, "r")
				except IOError:
					logger.info("File '%s' not found, nothing to parse." % absoluteFilepath)
					return
				
				if storeHash:	
					ruleFile.isParsed = True
					ruleFile.checksum = newHash
					ruleFile.save()
					
				it = iter(enumerate(infile))
				previous = ""
				for i,line in it:
					
					# Concatinate the current line with the previous
					line = previous + line
					previous = ""
					
					# If the line is incomplete, store what we have, and read next line.
					if(re.match(r"(.*)\\$",line)):
						previous = line.rstrip("\\\n")
					else:
						try:				
							fn(raw=line, **kwargs)
						except AbnormalRuleError:
							logger.info("Skipping abnormal rule in '%s'" % absoluteFilepath)
						except BadFormatError, e:
							# Log exception message, file name and line number
							logger.error("%s in file '%s', around line %s." % (str(e), absoluteFilepath, str(i)))							
			else :
				logger.info("Skipping file '%s', new and old hashes are identical." % absoluteFilepath)
		return parse

	def updateConfig(self, raw, filename, patterns):
		"""Method to parse an ASCII configuration-file for snort, with undefined content."""
		logger = logging.getLogger(__name__)

		if patterns['rule'].match(raw):
			logger.debug("Identified rule: %s" % raw)
			self.updateRule(raw, filename)
		elif patterns['reference'].match(raw):
			logger.debug("Identified reference: %s" % raw)
			self.updateReferenceConfig(raw)
		elif patterns['class'].match(raw):
			logger.debug("Identified Class: %s" % raw)
			self.updateClassification(raw)
		elif patterns['genmsg'].match(raw):
			logger.debug("Identified GEN-Msg: %s" % raw)
			self.updateGenMsg(raw)
		elif patterns['sidmsg'].match(raw):
			logger.debug("Identified SID-Msg: %s" % raw)
			self.updateSidMsg(raw)
		elif patterns['filter'].match(raw):
			logger.debug("Identified event_filter: %s" % raw)
			self.updateFilter(raw)
	
	def checkFilter(self, gid, sid, track, count, seconds, filterType=None):
		logger = logging.getLogger(__name__)

		try:
			if int(gid) and int(sid) and int(count) and int(seconds):
				pass
		except ValueError:
			message = "Badly formatted filter in rule "+str(sid)+": expected numeric value."
			logger.error(message)
			raise BadFormatError(message)

		if track != "by_src" and track != "by_dst":
			message = "Badly formatted filter in rule "+str(sid)+": invalid track parameter '"+track+"'."
			logger.error(message)
			raise BadFormatError(message)