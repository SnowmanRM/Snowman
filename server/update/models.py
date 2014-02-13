from django.db import models

from core.models import Rule, RuleSet, RuleRevision

class RuleChanges(models.Model):
	"""RuleChanges represents the changes in the rulesets performed by the update-procedure.
	It references to a rule, what set it was a member in, what set it should become member in,
	and if it has been moved. When we know that the operator is happy about the set the rule
	is in, we can safely delete the corresponding RuleChanges object."""
	
	rule = models.ForeignKey(Rule)
	originalSet = models.ForeignKey(RuleSet, related_name="rulechangeoriginal")
	newSet = models.ForeignKey(RuleSet, related_name="rulechangenew")
	update = models.ForeignKey('Update')
	moved = models.BooleanField()
	
	def __repr__(self):
		return "<RuleChanges SID:%d, fromSet:%s, toSet:%s, moved:%s>" % (self.rule.SID, 
				self.originalSet.name, self.newSet.name, str(self.moved))

	def __str__(self):
		return "<RuleChanges SID:%d, fromSet:%s, toSet:%s, moved:%s>" % (self.rule.SID, 
				self.originalSet.name, self.newSet.name, str(self.moved))

class Source(models.Model):
	"""A Source-object represents the different places we might get rule-updates from. If we have
	a stable url, we can even schedule regular updates from this source."""
	
	name = models.CharField(max_length=40)
	schedule = models.TimeField()
	url = models.CharField(max_length=80)
	lastMd5 = models.CharField(max_length=80)
	
	def __repr__(self):
		return "<Source name:%s, schedule:%s, url:%s, lastMd5:%s>" % (self.name, str(self.schedule), self.url, self.lastMd5)
	
	def __str__(self):
		return "<Source name:%s, schedule:%s, url:%s>" % (self.name, str(self.schedule), self.url)
	
class Update(models.Model):
	"""An Update-object is representing a single update of rules. This update happened at a time,
	it have a source, and a link to all the RuleRevisions that got updated."""
	
	time = models.DateField()
	source = models.ForeignKey('Source')
	ruleRevisions = models.ManyToManyField(RuleRevision)
	
	def __repr__(self):
		return "<Update source:%s, time:%s>" % (self.source.name, str(self.time))

	def __str__(self):
		return "<Update source:%s, time:%s>" % (self.source.name, str(self.time))

class UpdateFile(models.Model):
	"""An Update comes with several files. Each of the files is represented by an UpdateFile object."""

	name = models.CharField(max_length=40)
	update = models.ForeignKey('Update')
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

