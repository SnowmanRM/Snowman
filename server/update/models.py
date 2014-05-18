import datetime
import logging
import os
import re

from django.db import models, IntegrityError

from core.models import Generator, Rule, RuleSet, RuleRevision, RuleClass,\
	RuleReferenceType, Sensor, Comment
	
from update.exceptions import BadFormatError, AbnormalRuleError 
from core.exceptions import MissingObjectError

from util.config import Config
from util.patterns import ConfigPatterns
from util.tools import md5sum
from tuning.models import DetectionFilter, EventFilter

from util.constants import dbObjects
ALL_SENSORS = dbObjects.SENSORS_ALL

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
	
	class Meta:
		# Rule and update must be unique together
		unique_together = ('rule', 'update')
		
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
	
	name = models.CharField(max_length=40, unique=True)
	url = models.CharField(max_length=160, null=True)
	md5url = models.CharField(max_length=160, null=True)
	lastMd5 = models.CharField(max_length=80, null=True)
	schedule = models.CharField(max_length=40, default="No automatic updates")
	locked = models.BooleanField(default = False)
	
	def __repr__(self):
		return "<Source name:%s, schedule:%s, url:%s, md5url:%s, lastMd5:%s>" % (self.name, str(self.schedule), self.url, self.md5url, self.lastMd5)
	
	def __str__(self):
		return "<Source name:%s, schedule:%s, url:%s>" % (self.name, str(self.schedule), self.url)
	
	def setSchedule(self, data, save = True):
		"""Sets the schedule-string based on the content of a TimeSelectorForm."""
		if(data['newSourceForm'].cleaned_data['schedule'] == 'n'):
			self.schedule = "No automatic updates"
		else:
			self.schedule = str(data['timeSelector'].cleaned_data['minute']) + " "
			self.schedule += str(data['timeSelector'].cleaned_data['hour']) + " "

			if(data['newSourceForm'].cleaned_data['schedule'] == 'm'):
				self.schedule += str(data['timeSelector'].cleaned_data['day']) + " * "
			else:
				self.schedule += "* * "
			
			if(data['newSourceForm'].cleaned_data['schedule'] == 'w'):
				self.schedule += str(int(data['timeSelector'].cleaned_data['day']) % 7)
			else:
				self.schedule += "*"

		if(save):
			self.save()
	
	def getSchedule(self):
		"""Parses the schedule-string, and returns the contents in a dictionary."""
		d = {}
		
		if(self.schedule == None):
			self.schedule = "No automatic updates"
			self.save()
		
		# Extract the relevant groups from the schedule-field.
		pattern = re.compile(r"([\d\*]+)\ ([\d\*]+)\ ([\d\*]+)\ ([\d\*]+)\ ([\d\*]+)")
		match = pattern.match(self.schedule)
		
		if(match):
			groups = []
			for group in match.groups():
				if "*" in group:
					groups.append(None)
				else:
					groups.append(int(group))
			
			minute, hour, dom, mon, dow = groups
			
			d['minute'] = minute
			d['hour'] = hour
			
			if(dom):
				d['schedule'] = 'm'
				d['day'] = dom
			elif(dow):
				d['schedule'] = 'w'
				d['day'] = dow
			else:
				d['schedule'] = 'd'
		else:
			d['schedule'] = 'n'
		
		return d
	
class Update(models.Model):
	"""An Update-object is representing a single update of rules. This update happened at a time,
	it has a source, and a link to all the RuleRevisions that were updated."""
	
	time = models.DateTimeField()
	source = models.ForeignKey('Source', related_name="updates")
	ruleRevisions = models.ManyToManyField(RuleRevision, related_name="update")
	ruleSets = models.ManyToManyField(RuleSet, related_name="update")
	rules = models.ManyToManyField(Rule, related_name="update")
	isNew = models.BooleanField(default = True)
	
	def __repr__(self):
		return "<Update source:%s, time:%s>" % (self.source.name, str(self.time))

	def __str__(self):
		return "<Update source:%s, time:%s>" % (self.source.name, str(self.time))

class UpdateFile(models.Model):
	"""An Update comes with several files. Each of the files is represented by an UpdateFile object."""

	name = models.CharField(max_length = 250)
	source = models.ForeignKey('Source', related_name="files")
	checksum = models.CharField(max_length=80)
	isParsed = models.BooleanField()
	
	class Meta:
		# name and update must be unique together
		unique_together = ('name', 'source')		
	
	def __repr__(self):
		return "<UpdateFile name:%s, update:%s-%s, md5:%s>" % (self.name, self.update.source.name, self.update.time, self.checksum)

	def __str__(self):
		return "<UpdateFile name:%s, update:%s-%s>" % (self.name, self.update.source.name, self.update.time)

class UpdateLog(models.Model):
	"""The Log is the place an update stores the events that is happening while parsing a ruleset.
	The webinterface uses the log to tell the user the status of the on-going update."""
	
	MESSAGE = 1
	PROGRESS = 2
	
	update = models.ForeignKey('Update', related_name="logEntries")
	logType = models.IntegerField(default = 1)
	time = models.DateTimeField(default = datetime.datetime.now())
	text = models.CharField(max_length = 250)
	
	def __repr__(self):
		return "<Log update:%s-%s, time:%s, text:%s>" % (self.update.source.name, self.update.time, self.time, self.text)
	
	def __str__(self):
		return "<Log update:%s-%s, time:%s, text:%s>" % (self.update.source.name, self.update.time, self.time, self.text)
