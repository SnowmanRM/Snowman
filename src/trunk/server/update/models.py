from django.db import models
import logging
import re

from core.models import Generator, Rule, RuleSet, RuleRevision, RuleClass
from update.exceptions import BadFormatError


class RuleChanges(models.Model):
	"""RuleChanges represents the changes in the rulesets performed by the update-procedure.
	It references to a rule, what set it was a member in, what set it should become member in,
	and if it has been moved. When we know that the operator is happy about the set the rule
	is in, we can safely delete the corresponding RuleChanges object."""
	
	rule = models.ForeignKey(Rule)
	originalSet = models.ForeignKey(RuleSet, related_name="rulechangeoriginal")
	newSet = models.ForeignKey(RuleSet, related_name="rulechangenew")
	update = models.ForeignKey('Update', related_name="pendingChanges")
	moved = models.BooleanField()
	
	def __repr__(self):
		return "<RuleChanges SID:%d, fromSet:%s, toSet:%s, moved:%s>" % (self.rule.SID, 
				self.originalSet.name, self.newSet.name, str(self.moved))

	def __str__(self):
		return "<RuleChanges SID:%d, fromSet:%s, toSet:%s, moved:%s>" % (self.rule.SID, 
				self.originalSet.name, self.newSet.name, str(self.moved))

class Source(models.Model):
	"""A Source-object represents the different places we might get rule-updates from. If we have
	a stable url, we can even schedule regular updates from this source.
	
	The schedule is a cron-style string (30 0 * * 0 = 0:30 every sunday)"""
	
	name = models.CharField(max_length=40)
	url = models.CharField(max_length=80)
	lastMd5 = models.CharField(max_length=80)
	schedule = models.CharField(max_length=40)
	
	def __repr__(self):
		return "<Source name:%s, schedule:%s, url:%s, lastMd5:%s>" % (self.name, str(self.schedule), self.url, self.lastMd5)
	
	def __str__(self):
		return "<Source name:%s, schedule:%s, url:%s>" % (self.name, str(self.schedule), self.url)
	
class Update(models.Model):
	"""An Update-object is representing a single update of rules. This update happened at a time,
	it has a source, and a link to all the RuleRevisions that were updated."""
	
	time = models.DateTimeField()
	source = models.ForeignKey('Source', related_name="updates")
	ruleRevisions = models.ManyToManyField(RuleRevision)
	
	def __repr__(self):
		return "<Update source:%s, time:%s>" % (self.source.name, str(self.time))

	def __str__(self):
		return "<Update source:%s, time:%s>" % (self.source.name, str(self.time))

	def parseRuleFile(self, path):
		"""This method opens a rule-file, and parses it for all the found rules, and updated the
		database with the new rules."""
		rulesets = {}
		ruleclasses = {}
		generators = {}
		currentRules = Rule.getRuleRevisions()
		
		rulefile = open(path, "r")
		for line in rulefile:
			self.updateRule(line, currentRules, rulesets, ruleclasses, generators)
	
	def updateRule(self, raw, currentRules = {}, rulesets = {}, ruleclasses = {}, generators = {}):
		"""This method takes a raw rule-string, parses it, and if it is a new rule, we 
		update the database.
		
		currentRules can be supplied (containing a list of all SID's as keys, and revs as data)
		to make it quicker to see if the current rule is newer than the ones already in the database.
		
		rulesets/ruleclasses is used as a cache to store the django-objects retrieved from the 
		database, so  that we in later calls to this method can use them for quicker access.
		(Memory is generally cheaper than dbAccess)"""
		
		logger = logging.getLogger(__name__)
		
		# TODO: Add support for rules where ruleset is not defined.
		
		# Construct a regex, so that we can extract all the interesting parameters from the raw rulestring.
		matchPattern = r"(.*)alert(?=.*sid:(\d+))(?=.*rev:(\d+))"
		matchPattern += r"(?=.*ruleset (.*?)[,;])"
		matchPattern += r"(?=.*msg:\"(.*?)\";)"
		matchPattern += r"(?=.*classtype:(.*?);)"
		pattern = re.compile(matchPattern)
		
		# If the raw rule matched the regex: 
		result = pattern.match(raw)
		if(result):			
			# Assign some helpful variable-names:
			if("#" in result.group(1)):
				ruleActive = False
			else:
				ruleActive = True
			ruleSID = result.group(2)
			ruleRev = result.group(3)
			ruleSetName = result.group(4)
			ruleMessage = result.group(5)
			ruleClassName = result.group(6)
			ruleGID = 1
			
			# If the rule is new, or is a newer version of a rule we already have:
			if(int(ruleSID) not in currentRules or int(ruleRev) > currentRules[int(ruleSID)]):
				# Grab the correct ruleset from cache/db, or create a new one if it doesn't exist.
				try:
					ruleset = rulesets[ruleSetName]
				except KeyError:
					try:
						ruleset = RuleSet.objects.get(name = ruleSetName)
					except RuleSet.DoesNotExist:
						ruleset = RuleSet.objects.create(name = ruleSetName, description=ruleSetName, active=True)
						logger.info("Created new ruleset (" + str(ruleset) + ") while importing rule")
					rulesets[ruleSetName] = ruleset
						
				# Grab the correct ruleclass from cache/db, or create a new one if doesn't exist.
				try:
					ruleclass = ruleclasses[ruleClassName]
				except KeyError:
					try:
						ruleclass = RuleClass.objects.get(classtype=ruleClassName)
					except RuleClass.DoesNotExist:
						ruleclass = RuleClass.objects.create(classtype=ruleClassName, description=ruleClassName, priority=4)
						logger.info("Created new ruleclass (" + str(ruleclass) + ") while importing rule")
					ruleclasses[ruleClassName] = ruleclass
					
				# Grab the correct generator from cache/db, or create a new one if doesn't exist.
				try:
					generator = generators[ruleGID]
				except KeyError:
					try:
						generator = Generator.objects.get(GID=ruleGID)
					except RuleClass.DoesNotExist:
						generator = Generator.objects.create(GID=ruleGID, alertID=1, message="Automaticly created during update")
						logger.info("Created new generator (" + str(generator) + ") while importing rule")
					ruleclasses[ruleClassName] = ruleclass
					
				# Grab the rule-object, or create a new one if it doesn't exist.
				try:
					rule = Rule.objects.get(SID=ruleSID)
					rule.active = ruleActive
					# TODO: Handle logic moving rule to new set
					rule.ruleClass = ruleclass
					rule.generator = generator
					rule.save()
					logger.info("Updated rule:" + str(rule))
				except Rule.DoesNotExist:
					rule = Rule.objects.create(SID=int(ruleSID), generator=generator, active=ruleActive, ruleSet=ruleset, ruleClass=ruleclass)
					logger.info("Created a new rule: " + str(rule))
				
				rev = rule.updateRule(raw, ruleRev, ruleActive, ruleMessage)
				if(rev):
					self.ruleRevisions.add(rev)
			else:
				logger.debug("Rule %s/%s is already up to date" % (ruleSID, ruleRev))
				
	def parseClassificationFile(self, path):
		"""Method for parsing classification.config. File is read line by line
		and classifications are updated in the database."""
		
		logger = logging.getLogger(__name__)
				
		classificationFile = open(path, "r")
		for i,line in enumerate(classificationFile):
			try:
				self.updateClassification(line)
			except BadFormatError, e:
				# Log exception message, file name and line number
				logger.error("%s in file '%s', line " % (str(e), path, str(i+1)))
			
	def updateClassification(self, raw):
		"""Method for updating the database with a new classification.
		Classification data consists of three comma-separated strings which are
		extracted with a regex, and split up in the three respective parts:
		classtype, description and priority. The classtype is looked up in the
		database and if found, the object is overwritten with the new data. Else,
		a new classification object is inserted into the database."""
		
		# Regex: Match "config classification: " (group 0),
		# and everything that comes after (group 1), which is the classification data. 
		matchPattern = "config classification: (.*)"
		pattern = re.compile(matchPattern)
		result = pattern.match(raw)
		
		if(result):
			# Split the data and store as separate strings
			classification = result.group(1).split(",")
			
			try:
				try:
					# Update existing classification
					ruleclassification = RuleClass.objects.get(classtype=classification[0])
					ruleclassification.description = classification[1]
					ruleclassification.priority = classification[2]
					ruleclassification.save()
				except RuleClass.DoesNotExist:
					# Add new classification
					RuleClass.objects.create(classtype=classification[0], description=classification[1], priority=classification[2])
			except IndexError:
				# If one or more indexes are invalid, the classification is badly formatted
				raise BadFormatError("Badly formatted rule classification")
				
class UpdateFile(models.Model):
	"""An Update comes with several files. Each of the files is represented by an UpdateFile object."""

	name = models.CharField(max_length=40)
	update = models.ForeignKey('Update', related_name="files")
	checksum = models.CharField(max_length=80)
	
	def __repr__(self):
		return "<UpdateFile name:%s, update:%s-%s, md5:%s>" % (self.name, self.update.source.name, self.update.time, self.checksum)

	def __str__(self):
		return "<UpdateFile name:%s, update:%s-%s>" % (self.name, self.update.source.name, self.update.time)

class StaticFile(UpdateFile):
	"""Some of the files in an update should be delivered to the sensors without further processing.
	These files are represented by a StaticFile-object instead of an UpdateFile. (StaticFile inherits
	all of UpdateFile's properties."""

	path = models.CharField(max_length=120)
	
	def __repr__(self):
		return "<StaticFile name:%s, update:%s-%s, path:%s, md5:%s>" % (self.name, self.update.source.name, self.update.time, self.path, self.checksum)
	
	def __str__(self):
		return "<StaticFile name:%s, update:%s-%s, path:%s>" % (self.name, self.update.source.name, self.update.time, self.path)

