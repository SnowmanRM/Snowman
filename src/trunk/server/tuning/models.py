from django.db import models

from core.models import Rule, Sensor, Comment

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
		return "<Suppress Rule:%d, Sensor:%s track:%s>" % (self.rule.SID, self.sensor.name, Suppress.TRACK[self.track])

	def __str__(self):
		return "<Suppress Rule:%d, Sensor:%s>" % (self.rule.SID, self.sensor.name)
	
	def getAddresses(self):
		addresslist = []
		for address in self.addresses.all():
			addresslist.append(address.ipAddress)
		return addresslist
	
	def getConfigLine(self):
		line = "suppress gen_id = 1, sig_id = %d, track = %s, ip =" % (self.rule.SID, Suppress.TRACK[self.track])
		for address in self.getAddresses():
			line += " %s" % address
		return line

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
	"""Class modeling a detection_filter. Only one per rule per sensor allowed."""
	
	# Constants for the "track" parametre
	TRACK = {1: "source", 2: "destination"}
	SOURCE = 1
	DESTINATION = 2

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
		return "<DetectionFilter Rule:%d, Sensor:%s, comment:'%s', track:%s, count:%d, seconds:%d>" % (self.rule.SID, self.sensor.name, 
					self.comment, DetectionFilter.TRACK[self.track], self.count, self.seconds)

	def __str__(self):
		return "<DetectionFilter Rule:%d, Sensor:%s, comment:'%s'>" % (self.rule.SID, self.sensor.name, self.comment)

	def getRaw(self):
		if(self.track == DetectionFilter.SOURCE):
			track = "by_src"
		else:
			track = "by_dst"
		return "detection-filter: track %s, count %d, seconds %d; " % (track, self.count, self.seconds)

		
class EventFilter(models.Model):
	"""Class modeling an event_filter. Only one per rule per sensor allowed."""

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
	
	def getConfigLine(self):
		if(self.track == EventFilter.SOURCE):
			track = "by_src"
		else:
			track = "by_dst"

		return "event_filter gen_id 1, sig_id %d, type %s, track %s, count %d, seconds %d" % (self.rule.SID, EventFilter.TYPE[self.eventFilterType], track, self.count, self.seconds)

