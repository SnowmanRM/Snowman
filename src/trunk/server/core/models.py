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

	def __unicode__(self):
		return str(self.SID)

class RuleClass(models.Model):
	classtype = models.CharField(max_length=80)
	description = models.TextField()
	priority = models.IntegerField()
	
	def __unicode__(self):
		return self.classtype

class RuleReference(models.Model):
	reference = models.CharField(max_length=80)
	referenceType = models.ForeignKey('RuleReferenceType')
	rulerevision = models.ForeignKey('RuleRevision')

	def __unicode__(self):
		return self.reference

class RuleReferenceType(models.Model):
	name = models.CharField(max_length=30)
	urlPrefix = models.CharField(max_length=80)

	def __unicode__(self):
		return self.name

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

	def __unicode__(self):
		return "SID:" + str(self.rule.SID) + " rev:" + str(self.rev)

class RuleSet(models.Model):
	"""A RuleSet, is a set of rules. Alle Rule objects should have
	a reference to the ruleset they belong. The RuleSet object should
	only contain the metainfo for the set. Name, description, and 
	wheter it should be active or not."""

	name = models.CharField(max_length=30)
	parent = models.ForeignKey('RuleSet')
	description = models.TextField()
	active = models.BooleanField()

	def __unicode__(self):
		return self.name

class Sensor(models.Model):
	"""A Sensor is information on one SnortSensor installation. It 
	contains name, address and the secret used for authentication."""

	parent = models.ForeignKey('Sensor', null=True)
	name = models.CharField(max_length=30)
	active = models.BooleanField(default=True)
	ipAddress = models.CharField(max_length=38)
	secret = models.CharField(max_length=30)
	ruleSets = models.ManyToManyField('RuleSet')

	def __unicode__(self):
		return self.name
