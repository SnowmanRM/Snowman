from django.db import models
import logging
import re

from core.models import Generator, Rule, RuleSet, RuleRevision, RuleClass
from srm.settings import DATABASES


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
	it have a source, and a link to all the RuleRevisions that got updated."""
	
	time = models.DateTimeField()
	source = models.ForeignKey('Source', related_name="updates")
	ruleRevisions = models.ManyToManyField(RuleRevision)
	
	def __repr__(self):
		return "<Update source:%s, time:%s>" % (self.source.name, str(self.time))

	def __str__(self):
		return "<Update source:%s, time:%s>" % (self.source.name, str(self.time))
	
	def getRuleVersions(self):
		"""This method creates a dictionary where the key is the SID, and the data is the rev of the newest rule.
		Useful for efficient comparing of the SID/rev with the new rules, without collecting all the rule-data
		from the database."""
		logger = logging.getLogger(__name__)
		result = {}
		
		# If we use a MySQL-Database, we can ask it directly for the data, to optimize the queries a bit.
		if(DATABASES['default']['ENGINE'] == "django.db.backends.mysql"):
			# To prevent warnings about missing mysql-libraries, only include them when we actually need it. 
			import MySQLdb
			logger.debug("Collecting all SID/rev pairs from the database, using MySQL directly.")
			dbHost = DATABASES['default']['HOST']
			
			# If the host is not listed in the configfile, use localhost.
			if(len(dbHost) == 0):
				dbHost = "localhost"
				
			dbConnection = MySQLdb.connect(host=dbHost, user=DATABASES['default']['USER'],
										passwd=DATABASES['default']['PASSWORD'], 
										db=DATABASES['default']['NAME'])
			dbCursor = dbConnection.cursor()
			
			# Grab all SID's from the database
			dbCursor.execute("SELECT id,SID FROM core_rule")
			sid = dbCursor.fetchall()
			
			# Grab all the latest rev-numbers from the database,
			dbCursor.execute("SELECT DISTINCT rule_id, rev FROM core_rulerevision ORDER BY ID DESC")
			rev = dbCursor.fetchall()
			
			# Add the revs to a dictionary, where the key is the rule_id.
			revs = {}
			for r in rev:
				revs[int(r[0])] = int(r[1])
			
			# Match all the SID's with their corresponding rev's.
			for s in sid:
				try:
					result[int(s[1])] = revs[int(s[0])]
				except KeyError:
					logger.debug("SID %d has no rev." % int(s[1]))
			
			# Close the database-connection.
			dbCursor.close()
			dbConnection.close()
		
		# If we use any other type of database, collect the data using the django models.
		else:
			logger.debug("Collectiong all SID/rev pairs from the database, using the django-models")
			
			for rule in Rule.objects.all():
				result[rule.SID] = rule.revisions.latest(field_name = 'rev').rev
		
		return result
	
	def parseRuleFile(self, path):
		"""This method opens a rule-file, and parses it for all the found rules, and updated the
		database with the new rules."""
		rs = {}
		rc = {}
		gen = {}
		currentRules = self.getRuleVersions()
		
		rulefile = open(path, "r")
		for line in rulefile:
			self.updateRule(line, currentRules, rs, rc, gen)
	
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
		
		# Construct a regex, so that we can extract all the interesting parametres from the raw rulestring.
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
				# Grab the correct ruleset from cache/db, or create a new one if it doesnt exist.
				try:
					ruleset = rulesets[ruleSetName]
				except KeyError:
					try:
						ruleset = RuleSet.objects.get(name = ruleSetName)
					except RuleSet.DoesNotExist:
						ruleset = RuleSet.objects.create(name = ruleSetName, description=ruleSetName, active=True)
						logger.info("Created new ruleset (" + str(ruleset) + ") while importing rule")
					rulesets[ruleSetName] = ruleset
						
				# Grab the correct ruleclass from cache/db, or create a new one if doesnt exist.
				try:
					ruleclass = ruleclasses[ruleClassName]
				except KeyError:
					try:
						ruleclass = RuleClass.objects.get(classtype=ruleClassName)
					except RuleClass.DoesNotExist:
						ruleclass = RuleClass.objects.create(classtype=ruleClassName, description=ruleClassName, priority=4)
						logger.info("Created new ruleclass (" + str(ruleclass) + ") while importing rule")
					ruleclasses[ruleClassName] = ruleclass
					
				# Grab the correct generator from cache/db, or create a new one if doesnt exist.
				try:
					generator = generators[ruleGID]
				except KeyError:
					try:
						generator = Generator.objects.get(GID=ruleGID)
					except RuleClass.DoesNotExist:
						generator = Generator.objects.create(GID=ruleGID, alertID=1, message="Automaticly created during update")
						logger.info("Created new generator (" + str(generator) + ") while importing rule")
					ruleclasses[ruleClassName] = ruleclass
					
				# Grab the rule-object, or create a new one if it doesnt exist.
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

