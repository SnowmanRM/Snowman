from django.db import models

from core.models import Rule, Sensor, Comment


class RuleModifier(models.Model):
	"""The RuleModifier let us modifiy if a rule should be present on
	a sensor or not, regardless of what the ruleset says."""
	rule = models.ForeignKey(Rule, related_name = 'modifiers')
	sensor = models.ForeignKey(Sensor, related_name = 'ruleModifiers')
	active = models.NullBooleanField()
	
	def __repr__(self):
		return "<RuleModifier Rule:%d, Sensor:%s, active:%s>" % (self.rule.SID, self.sensor.name, str(self.active))

	def __str__(self):
		return "<RuleModifier Rule:%d, Sensor:%s, active:%s>" % (self.rule.SID, self.sensor.name, str(self.active))

class Suppress(models.Model):
	"""The suppress lets us suppress warnings from a specific rule on a
	specific sensor, if the rule is matching listed source or destination
	addresses."""

	# Constants for the "track" parametre
	TRACK = {1: "source", 2: "destination"}
	SOURCE = 1
	DESTINATION = 2
	
	rule = models.ForeignKey(Rule, related_name = 'suppress')
	sensor = models.ForeignKey(Sensor, related_name = 'suppress')
	comment = models.ForeignKey(Comment, related_name= 'suppress', null=True, on_delete=models.SET_NULL)
	track = models.IntegerField()
	
	def __repr__(self):
		return "<Suppress Rule:%d, Sensor:%s, comment:'%s', track:%s>" % (self.rule.SID, self.sensor.name, self.comment.comment, Suppress.TRACK[self.track])

	def __str__(self):
		return "<Suppress Rule:%d, Sensor:%s, comment:'%s'>" % (self.rule.SID, self.sensor.name, self.comment.comment)
	
	def getAddresses(self):
		addresslist = []
		for address in self.addresses.all():
			addresslist.append(address.ipAddress)
		return addresslist

class SuppressAddress(models.Model):
	"""SupressAddress is simply a container for an address that is
	assigned to a Suppress"""
	
	suppress = models.ManyToManyField('Suppress', related_name = 'addresses')
	ipAddress = models.CharField(max_length = 38)
	
	def __repr__(self):
		return "<SupressAddress %s>" % (self.ipAddress)
	
	def __str__(self):
		return "<SupressAddress %s>" % (self.ipAddress)

class DetectionFilter(models.Model):
	
	rule = models.ForeignKey(Rule, related_name = 'detectionFilters')
	sensor = models.ForeignKey(Sensor, related_name = 'detectionFilters')
	comment = models.ForeignKey(Comment, related_name= 'detectionFilters', null=True, on_delete=models.SET_NULL)
	track = models.IntegerField()
	count = models.IntegerField()
	seconds = models.IntegerField()
	
	class Meta:
		# Only one filter allowed per rule per sensor
		unique_together = ("rule", "sensor")

	def __repr__(self):
		return "<EventFilter Rule:%d, Sensor:%s, comment:'%s', type:%s, track:%s, count:%d, seconds:%d>" % (self.rule.SID, self.sensor.name, 
					self.comment, EventFilter.TYPE[self.eventFilterType], EventFilter.TRACK[self.track], self.count, self.seconds)

	def __str__(self):
		return "<EventFilter Rule:%d, Sensor:%s, comment:'%s'>" % (self.rule.SID, self.sensor.name, self.comment)
		
class EventFilter(models.Model):
	"""EventFilter are assigne to a specific rule on a specific sensor,
	and lets us put a certain type of EventFilters to this rule."""

	# Constants for the "eventFilterType" parametre
	TYPE = {1: "limit", 2: "threshold", 3:"both"}
	LIMIT = 1
	THRESHOLD = 2
	BOTH = 3
	
	# Constants for the "track" parametre
	TRACK = {1: "source", 2: "destination"}
	SOURCE = 1
	DESTINATION = 2
	
	rule = models.ForeignKey(Rule, related_name = 'eventFilters')
	sensor = models.ForeignKey(Sensor, related_name = 'eventFilters')
	comment = models.ForeignKey(Comment, related_name= 'eventFilters', null=True, on_delete=models.SET_NULL)
	eventFilterType = models.IntegerField()
	track = models.IntegerField()
	count = models.IntegerField()
	seconds = models.IntegerField()
	
	class Meta:
		# Only one filter allowed per rule per sensor
		unique_together = ("rule", "sensor")

	def __repr__(self):
		return "<EventFilter Rule:%d, Sensor:%s, comment:'%s', type:%s, track:%s, count:%d, seconds:%d>" % (self.rule.SID, self.sensor.name, 
					self.comment.comment, EventFilter.TYPE[self.eventFilterType], EventFilter.TRACK[self.track], self.count, self.seconds)

	def __str__(self):
		return "<EventFilter Rule:%d, Sensor:%s, comment:'%s'>" % (self.rule.SID, self.sensor.name, self.comment.comment)

