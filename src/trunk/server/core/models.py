from django.db import models

"""This python-model contains the data-models for the core
data. This includes the Rules and revisions, Rulesets, RuleClasses,
RuleReferences and Sensors."""

class Rule(models.Model):
	"""The Rule class contains only some meta-info about a specific
	rule. The SID, if the rule should be active, and to which ruleset
	this rule should belong to is the relevant data to store here.
	
	The real data of the rule should be stored in a RuleRevision."""

	SID = models.IntegerField()
	active = models.BooleanField()
	ruleSet = models.ForeignKey('RuleSet')
	ruleClass = models.ForeignKey('RuleClass')

	def __repr__(self):
		return "<Rule SID:%d, Active:%s, Set:%s, Class:%s>" % (self.SID, str(self.active), self.ruleSet.name, self.ruleClass.classtype)

	def __str__(self):
		return "<Rule SID:%d>" % (self.SID)

class RuleClass(models.Model):
	"""A ruleclass have a name, and a priority. All Rule objects should
	be a part of a RuleClass"""

	classtype = models.CharField(max_length=80)
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
	
	reference = models.CharField(max_length=80)
	referenceType = models.ForeignKey('RuleReferenceType')
	rulerevision = models.ForeignKey('RuleRevision')

	def __repr__(self):
		return "<RuleReference Type:%s, Reference:'%s', Rule(SID/rev):%d/%d>" % (self.referenceType.name, self.reference, self.rulerevision.rule.SID, self.rulerevision.rev)

	def __str__(self):
		return "<RuleReference Type:%s, Reference:'%s', Rule(SID/rev):%d/%d>" % (self.referenceType.name, self.reference, self.rulerevision.rule.SID, self.rulerevision.rev)

class RuleReferenceType(models.Model):
	""" RuleReferenceType is the different types a certain rulereference
	might be. It contains a name, which we find in the raw rules, and a
	urlPrefix """

	name = models.CharField(max_length=30)
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

	rule = models.ForeignKey('Rule')
	active = models.BooleanField(default=True)
	rev = models.IntegerField()
	raw = models.TextField()
	msg = models.TextField()

	def __repr__(self):
		return "<RuleRevision SID:%d, rev:%d, active:%s raw:'%s', msg:'%s'>" % (self.rule.SID, self.rev, str(self.active), self.raw, self.msg)

	def __str__(self):
		return "<RuleRevision SID:%d, rev:%d, active:%s raw:'%s', msg:'%s'>" % (self.rule.SID, self.rev, str(self.active), self.raw, self.msg)

class RuleSet(models.Model):
	"""A RuleSet, is a set of rules. Alle Rule objects should have
	a reference to the ruleset they belong. The RuleSet object should
	only contain the metainfo for the set. Name, description, and 
	wheter it should be active or not."""

	name = models.CharField(max_length=30)
	parent = models.ForeignKey('RuleSet', null=True)
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

	parent = models.ForeignKey('Sensor', null=True)
	name = models.CharField(max_length=30)
	active = models.BooleanField(default=True)
	ipAddress = models.CharField(max_length=38)
	secret = models.CharField(max_length=30)
	ruleSets = models.ManyToManyField('RuleSet')

	def __repr__(self):
		if(self.parent):
			return "<Sensor name:%s, parent:%s, active:%s, ipAddress:'%s', secret:%s>" % (self.name, self.parent.name, str(self.active), self.ipAddress, self.secret)
		else:
			return "<Sensor name:%s, parent:None, active:%s, ipAddress:'%s', secret:%s>" % (self.name, str(self.active), self.ipAddress, self.secret)

	def __str__(self):
		return "<Sensor name:%s, ipAddress:'%s'>" % (self.name, self.ipAddress)
