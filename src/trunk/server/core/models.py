import logging

from django.db import models
from django.contrib.auth.models import User

from srm.settings import DATABASES

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
	
	def natural_key(self):
		"""This method is used by serializers when use_natural_key is set in their method call to serialize another object.
		If that object has a reference to this object by foreign key, the serialization will also include this return string.
		
		This return string is a dictionary of the Rule variables; SID, Active, Set, Class and Priority.
		"""
		
		return {'SID': self.SID, 'Active': str(self.active), 'Set': self.ruleSet.name, 'Class': self.ruleClass.classtype, 'Priority': str(self.priority)}
	
	def json(self):	
		"""This method returns a string ready to be json-ified. It is for testing purposes only.
		
		REMOVE IF NOT NEEDED ANYMORE
		"""
			
		return {'SID': self.SID, 'Active': str(self.active), 'Set': self.ruleSet.name, 'Class': self.ruleClass.classtype, 'Priority': str(self.priority)}
	
	def getCurrentRevision(self):
			
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
			rev = RuleRevision.objects.create(rule=self, rev=int(rev), active=True, msg=msg, raw=raw)
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
	
	reference = models.TextField()
	referenceType = models.ForeignKey('RuleReferenceType', related_name='references')
	rulerevision = models.ForeignKey('RuleRevision', related_name='references')

	# TODO: Unique: rulerevision+referencetype? 

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
	"""This class should represent a single revision of a rule. Every
	time a rule is updated, there should be created a new object of 
	this class.
	The active-field should signal if this revision is a revision we
	want to use. When a Rule is fetched, the revision with the highest
	rev that is active is selected as the correct rule to use."""

	rule = models.ForeignKey('Rule', related_name="revisions")
	active = models.BooleanField(default=True)
	rev = models.IntegerField()
	raw = models.TextField()
	msg = models.TextField()

	def __repr__(self):
		return "<RuleRevision SID:%d, rev:%d, active:%s raw:'%s', msg:'%s'>" % (self.rule.SID, self.rev, str(self.active), self.raw, self.msg)

	def __str__(self):
		return "<RuleRevision SID:%d, rev:%d, active:%s raw:'%s', msg:'%s'>" % (self.rule.SID, self.rev, str(self.active), self.raw, self.msg)
	
	def json(self):
		"""This method returns a string ready to be json-ified. It is for testing purposes only.
		
		REMOVE IF NOT NEEDED ANYMORE
		"""	
		return {'SID': self.rule.SID, 'rev': self.rev, 'active': str(self.active), 'raw': self.raw, 'msg': self.msg}

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

class Sensor(models.Model):
	"""A Sensor is information on one SnortSensor installation. It 
	contains name, address and the secret used for authentication."""

	parent = models.ForeignKey('Sensor', null=True, related_name='childSensors')
	name = models.CharField(max_length=30, unique=True)
	user = models.ForeignKey(User, related_name='sensor')
	active = models.BooleanField(default=True)
	autonomous = models.BooleanField(default=False)
	ipAddress = models.CharField(max_length=38, default="")
	ruleSets = models.ManyToManyField('RuleSet', related_name='sensors')

	def __repr__(self):
		if(self.parent):
			return "<Sensor name:%s, parent:%s, active:%s, ipAddress:'%s', user:%s>" % (self.name, self.parent.name, str(self.active), self.ipAddress, self.user.username)
		else:
			return "<Sensor name:%s, parent:None, active:%s, ipAddress:'%s', user:%s>" % (self.name, str(self.active), self.ipAddress, self.user.username)

	def __str__(self):
		return "<Sensor name:%s, ipAddress:'%s'>" % (self.name, self.ipAddress)
