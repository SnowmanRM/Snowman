#!/usr/bin/python
import datetime
import logging
import os
import sys 

from util.logger import initialize

from data.models import Session, Rule, RuleSet, RuleClass, Generator
from util.config import Config

class ConfigFile:
	"""A class which helps us to keep a nice format for our configfiles. It makes sure
	to include som comments in the top of the file, together with a timestamp. This way
	it is visible from where the file is, and when it is created."""

	def __init__(self, filename):
		"""Store the filename, open a filedescriptor, and print the beginning comments 
		the file."""
		self.filename = filename
		self.file = open(self.filename, "w")
		self.file.write("# This file is automaticly created by Snowman\n")
		self.file.write("# Creationtime: %s\n\n" % str(datetime.datetime.now()))
	
	def addLine(self, line):
		"""Adds a string to the cofigfile, followed by a string."""
		self.file.write("%s\n" % line)
	
	def close(self):
		"""Closes the filedescriptor."""
		self.file.close()

class ConfigGenerator:
	"""A class made to help creating the configfiles needed by SNORT, based on
	the content of the local rule-database."""

	def __init__(self):
		"""Initializes internal data-structure, and makes sure that the folder
		where we are going to store the configurationfiles actually exists."""

		logger = logging.getLogger(__name__)
		self.configlocation = Config.get("configfiles", "location")
		self.configfiles = []
		
		if(os.path.exists(self.configlocation) == False):
			logger.warning("Location for the configfiles does not exist. Creating the folders.")
			os.makedirs(self.configlocation, 0755)
	
	def cleanup(self):
		for filename in os.listdir(self.configlocation):
			file_path = os.path.join(self.configlocation, filename)
			try:
				if ".rule" in filename:
					os.unlink(file_path)
			except Exception, e:
				print e
	
	def generateConfigFile(self, filename, elements, configFormat):
		"""Generates an arbritary configurationfile, with the name supplied as "filename".
		The method iterates trough elements, and hands them one and one to the method 
		supplied as configFormat. Whatever this method returns is written as one line in
		the configfile."""
		logger = logging.getLogger(__name__)
		logger.info("Starting to generate %s" % filename)
		
		configfile = ConfigFile(os.path.join(self.configlocation, filename))
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
		
		s = Session.session()
		sidmsg = ConfigFile(os.path.join(self.configlocation, "sid-msg.map"))
		
		# For every ruleset:
		for ruleset in s.query(RuleSet).all():
			# Create a configfile
			rulefile = ConfigFile(os.path.join(self.configlocation, "%s.rules" % ruleset.name))
			
			# For every rule in the ruleset:
			for rule in s.query(Rule).filter(Rule.ruleset_id == ruleset.id).all():
				# Print the rule to the configfile
				rulefile.addLine(rule.raw)

				# Start generate a line with sid/msg for sid-msg.map
				sidmsgstring = "%s || %s" % (rule.SID, rule.msg)
				# For evert reference this rule have:
				for ref in rule.references:
					# Append the reference to the line for sid-msg.map
					sidmsgstring += " || %s,%s" % (ref.referenceType.name, ref.reference)
				# Finally add the line to sid-msg.map
				sidmsg.addLine(sidmsgstring)
			
			# Close the rulefile, and add the name to the configfiles list.
			rulefile.close()
			self.configfiles.append("%s.rules" % ruleset.name)
		
		# When all rules are added, close sid-msg.map, and add the file to the configfiles list.
		sidmsg.close()
		self.configfiles.append("sid-msg.map")
		
		s.close()
	
	def generateIncludes(self):
		"""This method generates a file which includes all files this object have created.
		This is to have a simple way to configure snort to import all the files which are
		dynamically created."""
		self.generateConfigFile("snowman-includes.config", self.configfiles, lambda x: "include %s" % os.path.join(self.configlocation, x))
		
