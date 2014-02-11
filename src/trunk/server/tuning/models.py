from django.db import models

from core.models import Rule, Sensor

class RuleModifier(models.Model):
	rule = models.ForeignKey(Rule)
	sensor = models.ForeignKey(Sensor)
	active = models.NullBooleanField()

class Supress(models.Model):
	TRACK = (
    	(1, 'Source IP'),
    	(2, 'Destination IP'),
	)
	
	rule = models.ForeignKey(Rule)
	sensor = models.ForeignKey(Sensor)
	comment = models.TextField()
	track = models.IntegerField()
	count = models.IntegerField()
	seconds = models.IntegerField()

class SupressAddress(models.Model):
	supress = models.ForeignKey('Supress')
	ipAddress = models.CharField(max_length = 38)

class Threshold(models.Model):
	TYPE = (
    	(1, 'limit'),
    	(2, 'threshold'),
    	(3, 'both'),
	)
	TRACK = (
    	(1, 'Source IP'),
    	(2, 'Destination IP'),
	)
	
	rule = models.ForeignKey(Rule)
	sensor = models.ForeignKey(Sensor)
	comment = models.TextField()
	thresholdType = models.IntegerField()
	track = models.IntegerField()
