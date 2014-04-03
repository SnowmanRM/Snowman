import datetime
import logging
import re
import socket
import xmlrpclib

from django.db import models
from django.contrib.auth.models import User
from django.utils.timezone import utc

from util.tools import Replace, Timeout

from srm.settings import DATABASES
from util.config import Config

"""This python-model contains the data-models for the core
data. This includes the Rules and revisions, Rulesets, RuleClasses,
RuleReferences and Sensors."""

class Generator(models.Model):
	"""The Generator class is to hold the data of gen-msg.conf. Generators,
	AlertID's and messages."""

	GID = models.IntegerField()
	alertID = models.IntegerField()
	message = models.TextField()
	
	class Meta:
		# GID and alertID must be unique together
		unique_together = ('GID', 'alertID')	
	
	def __repr__(self):
		return "<Generator GID:%d, alertID:%d, message:\"%s\">" % (self.GID, self.alertID, self.message)
	
	def __str__(self):
		return "<Generator GID:%d, alertID:%d>" % (self.GID, self.alertID)

class Rule(models.Model):
	"""The Rule class contains only some meta-info about a specific
	rule. The SID, if the rule should be active, and to which ruleset
	this rule should belong to is the relevant data to store here.
	
	The real data of the rule should be stored in a RuleRevision."""

	SID = models.IntegerField(unique=True)
	active = models.BooleanField()
	generator = models.ForeignKey('Generator', related_name='rules')
	ruleSet = models.ForeignKey('RuleSet', related_name='rules')
	ruleClass = models.ForeignKey('RuleClass', related_name='rules')
	priority = models.IntegerField(null=True)

	def __repr__(self):
		return "<Rule SID:%d, Active:%s, Set:%s, Class:%s Priority:%s>" % (self.SID, 
					str(self.active), self.ruleSet.name, self.ruleClass.classtype, str(self.priority))

	def __str__(self):
		return "<Rule SID:%d>" % (self.SID)
	
	def getCurrentRevision(self):
		"""This method returns the most recent active rule-revision"""
		return self.revisions.filter(active=True).last()

	
	def updateRule(self, raw, rev = None, msg = None):
		"""This method recieves a rule, and if needed, creates a new RuleRevision object, and inserts into
		the list of revisions belonging to this rule. If the rev on the new rule is equal, or smaller than
		the last in revisions, nothing is done.
		
		If rev/active/msg is not supplied, they will be extracted from the raw string"""

		logger = logging.getLogger(__name__)

		# TODO: Parse raw for arguments that is not supplied by caller.
		
		# Try to grab the latest revision from the database
		try:
			lastRev = self.revisions.latest(field_name = 'rev')
		except RuleRevision.DoesNotExist:
			lastRev = None
		
		# If no revisions are found, or the last revision is smaller than the new one,
		#   add the new revision to the database.
		if(lastRev == None or int(lastRev.rev) < int(rev)):
			
			# Remove filters from raw string before storage:
			replace = Replace("")			
			filters = ""
			
			raw = re.sub(r'detection_filter:.*?;', replace, raw)
			filters += replace.matched or ""
			raw = re.sub(r'threshold:.*?;', replace, raw)
			filters += replace.matched or ""
			
			raw = " ".join(raw.split())
			rev = RuleRevision.objects.create(rule=self, rev=int(rev), active=True, msg=msg, raw=raw)
			rev.filters = filters
			rev.save()
			logger.debug("Updated rule-revision:" + str(rev))
			return rev
		
		return None
	
	@staticmethod
	def getRuleRevisions():
		"""This method is to get a list over the latest rules/revisions. 

		This method creates a dictionary where the key is the SID, and the data is the rev of the newest rule.
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
	
class RuleClass(models.Model):
	"""A ruleclass have a name, and a priority. All Rule objects should
	be a part of a RuleClass"""

	classtype = models.CharField(max_length=80,unique=True)
	description = models.TextField()
	priority = models.IntegerField()
	
	def __repr__(self):
		return "<RuleClass Type:%s, Description:'%s', Priority:%d>" % (self.classtype, self.description, self.priority)

	def __str__(self):
		return "<RuleClass Type:%s, Priority:%d>" % (self.classtype, self.priority)

class RuleReference(models.Model):
	"""A RuleReference contains information on where to find more info
	about a specific rule. It is of a certain type (which contains an
	urlPrefix), and a reference."""
	
	reference = models.CharField(max_length=250)
	referenceType = models.ForeignKey('RuleReferenceType', related_name='references')
	rulerevision = models.ForeignKey('RuleRevision', related_name='references')

	class Meta:
		# Avoid duplicate entries
		unique_together = ('reference', 'referenceType', 'rulerevision')

	def __repr__(self):
		return "<RuleReference Type:%s, Reference:'%s', Rule(SID/rev):%d/%d>" % (self.referenceType.name, 
					self.reference, self.rulerevision.rule.SID, self.rulerevision.rev)

	def __str__(self):
		return "<RuleReference Type:%s, Reference:'%s', Rule(SID/rev):%d/%d>" % (self.referenceType.name, 
					self.reference, self.rulerevision.rule.SID, self.rulerevision.rev)

	def splitReference(self):
		return 0

class RuleReferenceType(models.Model):
	""" RuleReferenceType is the different types a certain rulereference
	might be. It contains a name, which we find in the raw rules, and a
	urlPrefix """

	name = models.CharField(max_length=30, unique=True)
	urlPrefix = models.CharField(max_length=80)

	def __repr__(self):
		return "<RuleReferenceType name:%s, urlPrefix:'%s'>" % (self.name, self.urlPrefix)

	def __str__(self):
		return "<RuleReferenceType name:%s, urlPrefix:'%s'>" % (self.name, self.urlPrefix)

class RuleRevision(models.Model):
	"""Represents a single revision of a rule. Every
	time a rule is updated, a new revision object should be created.
	
	== FIELDS ==
	Raw: The text-string carrying the rule header and rule options. Known
	in this project as the rulestring.
	
	Msg: Alert message. 
	
	Active: The active-field determines if this revision is a revision we
	want to use. When a Rule is fetched, the revision with the highest
	rev that is active is selected as the correct rule to use.
	
	Filters: Inline filters such as detection filter and (now deprecated)
	threshold are stored as normal text-options in this field (as they
	appear in the original rulestring)."""

	raw = models.TextField()
	rev = models.IntegerField()
	msg = models.TextField()
	active = models.BooleanField(default=True)
	filters = models.TextField(default = "")
	rule = models.ForeignKey('Rule', related_name="revisions")

	def __repr__(self):
		return "<RuleRevision SID:%d, rev:%d, active:%s raw:'%s', msg:'%s'>" % (self.rule.SID, self.rev, str(self.active), self.raw, self.msg)

	def __str__(self):
		return "<RuleRevision SID:%d, rev:%d, active:%s raw:'%s', msg:'%s'>" % (self.rule.SID, self.rev, str(self.active), self.raw, self.msg)
	
	def getReferences(self):
		"""Returns a list of all the references that is related to this rule."""
		referenceList = []
		for ref in self.references.all():
			referenceList.append((ref.referenceType.name, ref.reference))
		return referenceList 

class RuleSet(models.Model):
	"""A RuleSet, is a set of rules. Alle Rule objects should have
	a reference to the ruleset they belong. The RuleSet object should
	only contain the metainfo for the set. Name, description, and 
	wheter it should be active or not."""

	name = models.CharField(max_length=100, unique=True)
	parent = models.ForeignKey('RuleSet', null=True, related_name='childSets')
	description = models.TextField()
	active = models.BooleanField()

	def __repr__(self):
		if(self.parent):
			return "<RuleSet name:%s, parent:%s, active:%s description:'%s'>" % (self.name, self.parent.name, str(self.active), self.description)
		else:
			return "<RuleSet name:%s, parent:None, active:%s description:'%s'>" % (self.name, str(self.active), self.description)

	def __str__(self):
		return "<RuleSet name:%s>" % (self.name)
	
	def __len__(self):
		noRules = self.rules.count()
		for ruleSet in self.childSets.all():
			noRules += len(ruleSet)
		return noRules
	
	def getRuleRevisions(self, active):
		"""This method returns a dictionary, where the key is the SID, and the data is the
		most recent rev, for all the rules that is in this (or any childs of this) RuleSet."""
		revisions = {}
		
		# Collect the rules in this ruleSet
		for rule in self.rules.all():
			if(active == None or active == rule.active):
				revisions[str(rule.SID)] = rule.getCurrentRevision().rev
		
		# Collect the sid of the rules in child-rulesets.
		for ruleSet in self.childSets.all():
			if ruleSet.active:
				revisions.update(ruleSet.getRuleRevisions(active))

		return revisions
	
	def getChildSets(self):
		"""This method returns a list of RuleSets, which is the children-sets (and their children)
		of this ruleset."""
		sets = []
		for childSet in self.childSets.all():
			if(childSet.active):
				sets.append(childSet)
				sets.extend(childSet.getChildSets())

		return sets	

class Sensor(models.Model):
	"""A Sensor is information on one SnortSensor installation. It 
	contains name, address and the secret used for authentication."""

	AVAILABLE = 0
	UNAVAILABLE = 1
	INACTIVE = 2
	AUTONOMOUS = 3
	UNKNOWN = 4
	
	parent = models.ForeignKey('Sensor', null=True, related_name='childSensors')
	name = models.CharField(max_length=30, unique=True)
	user = models.ForeignKey(User, related_name='sensor', null=True)
	active = models.BooleanField(default=True)
	autonomous = models.BooleanField(default=False)
	ipAddress = models.CharField(max_length=38, default="", null=True)
	ruleSets = models.ManyToManyField('RuleSet', related_name='sensors')
	lastChecked = models.DateTimeField(null=True)
	lastStatus = models.BooleanField(default=False)

	def __repr__(self):
		if(self.parent):
			return "<Sensor name:%s, parent:%s, active:%s, ipAddress:'%s'>" % (self.name, self.parent.name, str(self.active), self.ipAddress)
		else:
			return "<Sensor name:%s, parent:None, active:%s, ipAddress:'%s'>" % (self.name, str(self.active), self.ipAddress)

	def __str__(self):
		return "<Sensor name:%s, ipAddress:'%s'>" % (self.name, self.ipAddress)
	
	def pingSensor(self):
		"""This method checks the status of the sensor, to see if the snowman-clientd is running. It returns a dictionary,
		where 'status' contains a boolean value if the ping was successful, and 'message' contains a textual message of
		what happened."""
		logger = logging.getLogger(__name__)
		port = int(Config.get("sensor", "port"))
		timeout = int(Config.get("sensor", "pingTimeout"))
		sensor = xmlrpclib.Server("https://%s:%s" % (self.ipAddress, port))
		
		try:
			with Timeout(timeout):
				result = sensor.ping(self.name)
		except Timeout.Timeout:
			logger.warning("Ping to sensor timed out")
			return {'status': False, 'message': "Ping to sensor timed out"}
		except socket.gaierror:
			logger.warning("Could not ping sensor. Address is malformed")
			return {'status': False, 'message': "Could not ping sensor. Address is malformed"}
		except socket.error as e:
			logger.warning("Could not ping sensor. %s" % str(e))
			return {'status': False, 'message': "Could not ping sensor. %s" % str(e)}
		
		return result
	
	def requestUpdate(self):
		"""This method contacts the sensor, and asks it to do an update of its ruleset."""
		port = int(Config.get("sensor", "port"))
		sensor = xmlrpclib.Server("https://%s:%s" % (self.ipAddress, port))
		
		try:
			with Timeout(timeout):
				result = sensor.startUpdate(self.name)
		except Timeout.Timeout:
			logger.warning("Ping to sensor timed out")
			return {'status': False, 'message': "Ping to sensor timed out"}
		except socket.gaierror:
			logger.warning("Could not ping sensor. Address is malformed")
			return {'status': False, 'message': "Could not ping sensor. Address is malformed"}
		except socket.error as e:
			logger.warning("Could not ping sensor. %s" % str(e))
			return {'status': False, 'message': "Could not ping sensor. %s" % str(e)}
		
		return result
	
	def getStatus(self):
		"""This method checks the latest status from the sensor-checks, and returns the result. It returns one of the
		following values:
			Sensor.AUTONOMOUS - This is an autonomous sensor
			Sensor.INACTIVE - This sensor is not active
			Sensor.UNKNOWN - The status of this sensor is not checked recently (ie: more than 5 minutes ago).
			Sensor.AVAILABLE - This sensor is reachable.
			Sensor.UNAVAILABLE - This sensor is not able to be reached.
		"""
		if(self.autonomous):
			return self.AUTONOMOUS
		elif(not self.active):
			return self.INACTIVE
		elif(self.lastChecked == None or self.lastChecked + datetime.timedelta(minutes=5) < datetime.datetime.utcnow().replace(tzinfo=utc)):
			return self.UNKNOWN
		elif(self.lastStatus):
			return self.AVAILABLE
		else:
			return self.UNAVAILABLE
	
	def getChildCount(self):
		"""This method counts the number of child-sensors (and their childs), and returns the total number."""
		childCount = 0
		for child in self.childSensors.all():
			childCount += 1
			childCount += child.getChildCount()

		return childCount
	
	@staticmethod
	def refreshStatus():
		"""This method updates the status-information of all the sensors that is not autonomous."""
		for sensor in Sensor.objects.exclude(name="All").filter(autonomous=False).all():
			status = sensor.pingSensor()
			sensor.lastStatus = status['status']
			sensor.lastChecked = datetime.datetime.utcnow().replace(tzinfo=utc)
			sensor.save()

class Comment(models.Model):
	"""
	Comment objects are used to track important events in the system, with who, what and when.
	"""
	user = models.IntegerField()
	time = models.DateTimeField(default = datetime.datetime.now())
	comment = models.TextField()
	type = models.CharField(max_length=100, default="")
	foreignKey = models.IntegerField(null=True)
	
	def __repr__(self):
			return "<Comment user:%s, time:None, comment:%s, type:'%s', foreignKey:%s>" % (self.user, self.time, self.comment, self.foreignKey)

	def __str__(self):
		return "<Comment time:%s, type:'%s', comment:'%s'>" % (self.time, self.type, self.comment)
