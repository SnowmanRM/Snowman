#!/usr/bin/python
import datetime
import logging
import os
import re
import shutil
import sys 
import tempfile
import tarfile

from core.models import Sensor, RuleSet, RuleClass, Generator, RuleReferenceType
from tuning.tools import getDetectionFilter, getEventFilter, getSuppress
from util.configfile import ConfigFile

class ConfigGenerator:
	"""A class made to help creating the configfiles needed by SNORT, based on
	the content of the local rule-database."""

	def __init__(self, sensor):
		"""Initializes internal data-structure, and makes sure that the folder
		where we are going to store the configurationfiles actually exists."""

		logger = logging.getLogger(__name__)
		self.configlocation = tempfile.mkdtemp()
		self.configfiles = []
 		self.sensor = sensor
		self.rules = {}
		
	def generateConfig(self):
		self.generateConfigFile("classification.config", RuleClass.objects.all(), lambda x: "config classification: %s,%s,%d" % (x.classtype, x.description, int(x.priority)))
		self.generateConfigFile("gen-msg.map", Generator.objects.order_by("gid").order_by("GID", "alertID").all(), lambda x: "%d || %d || %s" % (x.GID, x.alertID, x.message))
		self.generateConfigFile("reference.config", RuleReferenceType.objects.all(), lambda x: "config reference: %s %s" % (x.name, x.urlPrefix))
		self.generateRuleFiles()
		self.generateIncludes()
		
		tar = tarfile.open("/tmp/%s.tar.gz" % self.sensor.name, "w:gz")
		tar.add(self.configlocation, arcname="rules/")
		tar.close()
		
		shutil.rmtree(self.configlocation)
		
		return "/tmp/%s.tar.gz" % self.sensor.name
	
	def generateConfigFile(self, filename, elements, configFormat, header = None):
		"""Generates an arbritary configurationfile, with the name supplied as "filename".
		The method iterates trough elements, and hands them one and one to the method 
		supplied as configFormat. Whatever this method returns is written as one line in
		the configfile."""
		logger = logging.getLogger(__name__)
		logger.info("Starting to generate %s" % filename)
		
		configfile = ConfigFile(os.path.join(self.configlocation, filename))
		if(header):
			configfile.addLine(header)
		
		for element in elements:
			configfile.addLine(configFormat(element))
		configfile.close()
		
		self.configfiles.append(filename)
		logger.info("Finished generation of %s" % filename)
	
	def generateRuleFiles(self):
		"""Iterates trough all the local rulesets, and prints all the rules in them to 
		corresponding rule-files. It is also in the same time generating sid-msg.map, 
		which contains all the sid/msg and references."""

		logger = logging.getLogger(__name__)
		logger.info("Starting to generate rule-files")
		
		sidmsg = ConfigFile(os.path.join(self.configlocation, "sid-msg.map"))
		filters = ConfigFile(os.path.join(self.configlocation, "filters.conf"))
		suppresses = ConfigFile(os.path.join(self.configlocation, "suppress.conf"))
		
		# Get the rulesets applied to this sensor:
		sets = {x.name: x for x in self.sensor.ruleSets.filter(active=True).all()}

		# Get the rulesets applied to any parent sensor:
		s = self.sensor.parent
		while s != None:
			sets.update({x.name: x for x in s.ruleSets.filter(active=True).all()})
			s = s.parent

		# Get all child-rulesets of the rulesets we already have found.
		ruleSets = {}
		for s in sets:
			ruleSets.update({x.name: x for x in sets[s].getChildSets()})
			ruleSets[s] = sets[s]
		
		# For every set we found, create a corresponding rules file
		for setname in ruleSets:
			ruleFile = ConfigFile(os.path.join(self.configlocation, "%s.rules" % setname))

			for rule in ruleSets[setname].rules.filter(active=True).all():
				rev = rule.getCurrentRevision()
				dFilter = getDetectionFilter(self.sensor, rule)
				eFilter = getEventFilter(self.sensor, rule)
				suppress = getSuppress(self.sensor, rule)
				
				# If the rule have a detectionFilter, inject it into the rule-string:
				if(dFilter):
					rawFilter = dFilter.getRaw()
					raw = output = re.sub(r'(.*)(sid.*\))', r'\1' + rawFilter + r'\2', rev.raw)
					ruleFile.addLine(raw)
				# Otherwise, just use the raw string.
				else:
					ruleFile.addLine(rev.raw)
				
				# Add the message to sidmsg.
				sidmsg.addLine("%d || %s" % (rule.SID, rev.msg))	
				
				# Add an eventual eventFilter
				if(eFilter):
					filters.addLine(eFilter.getConfigLine())
				
				# Add an detection-filter
				if(suppress):
					suppresses.addLine(suppress.getConfigLine())
			
			# Close the ruleFile
			ruleFile.close()
			self.configfiles.append("%s.rules" % setname)
		
		# When all rules are added, close sid-msg.map, and add the file to the configfiles list.
		sidmsg.close()
		filters.close()
		suppresses.close()
		self.configfiles.append("sid-msg.map")
		self.configfiles.append("filters.conf")
		self.configfiles.append("suppress.conf")
	
	def generateIncludes(self):
		"""This method generates a file which includes all files this object have created.
		This is to have a simple way to configure snort to import all the files which are
		dynamically created."""
		self.generateConfigFile("snowman-includes.config", self.configfiles, lambda x: "include $SNOWMAN-RULELOCATION/%s" % x, "var $SNOWMAN-RULELOCATION rules/\n")
