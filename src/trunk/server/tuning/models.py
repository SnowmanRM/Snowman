from django.db import models

from core.models import Rule, Sensor


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
	comment = models.TextField()
	track = models.IntegerField()
	
	def __repr__(self):
		return "<Suppress Rule:%d, Sensor:%s, comment:'%s', track:%s>" % (self.rule.SID, self.sensor.name, self.comment, Suppress.TRACK[self.track])

	def __str__(self):
		return "<Suppress Rule:%d, Sensor:%s, comment:'%s'>" % (self.rule.SID, self.sensor.name, self.comment)

class SuppressAddress(models.Model):
	"""SupressAddress is simply a container for an address that is
	assigned to a Suppress"""
	
	supress = models.ForeignKey('Suppress', related_name = 'addresses')
	ipAddress = models.CharField(max_length = 38)
	
	def __repr__(self):
		return "<SupressAddress %s>" % (self.ipAddress)
	
	def __str__(self):
		return "<SupressAddress %s>" % (self.ipAddress)
	
class Threshold(models.Model):
	"""Threshold are assigne to a specific rule on a specific sensor,
	and lets us put a certain type of thresholds to this rule."""

	# Constants for the "thresholdType" parametre
	TYPE = {1: "limit", 2: "threshold", 3:"both"}
	LIMIT = 1
	THRESHOLD = 2
	BOTH = 3
	
	# Constants for the "track" parametre
	TRACK = {1: "source", 2: "destination"}
	SOURCE = 1
	DESTINATION = 2
	
	rule = models.ForeignKey(Rule, related_name = 'thresholds')
	sensor = models.ForeignKey(Sensor, related_name = 'thresholds')
	comment = models.TextField()
	thresholdType = models.IntegerField()
	track = models.IntegerField()
	count = models.IntegerField()
	seconds = models.IntegerField()

	def __repr__(self):
		return "<Threshold Rule:%d, Sensor:%s, comment:'%s', type:%s, track:%s, count:%d, seconds:%d>" % (self.rule.SID, self.sensor.name, 
					self.comment, Threshold.TYPE[self.thresholdType], Threshold.TRACK[self.track], self.count, self.seconds)

	def __str__(self):
		return "<Threshold Rule:%d, Sensor:%s, comment:'%s'>" % (self.rule.SID, self.sensor.name, self.comment)

