from django.db import models

from core.models import Rule, RuleSet, RuleRevision

class RuleChanges(models.Model):
	rule = models.ForeignKey(Rule)
	originalSet = models.ForeignKey(RuleSet, related_name="rulechangeoriginal")
	newSet = models.ForeignKey(RuleSet, related_name="rulechangenew")
	update = models.ForeignKey('Update')
	moved = models.BooleanField()

class Source(models.Model):
	name = models.CharField(max_length=40)
	schedule = models.TimeField()
	url = models.CharField(max_length=80)
	lastMd5 = models.CharField(max_length=80)
	
class Update(models.Model):
	time = models.DateField()
	source = models.ForeignKey('Source')
	ruleRevisions = models.ManyToManyField(RuleRevision)

class UpdateFile(models.Model):
	name = models.CharField(max_length=40)
	update = models.ForeignKey('Update')
	checksum = models.CharField(max_length=80)

class StaticFile(UpdateFile):
	path = models.CharField(max_length=120)

