#!/usr/bin/python
"""
update.updater.Updater

The updater module is responsible to recieve the parsed rules, and store them in the database.
It will raise an TypeError if any of the data is of wrong types..
"""

import logging

from core.models import Generator, Rule, RuleSet, RuleClass, RuleReference, RuleReferenceType
from tuning.models import Suppress, SuppressAddress, DetectionFilter, EventFilter
from util.config import Config

class Updater():
	RAW = 0
	NEW = 1
	CHANGED = 2
	SAVED = 3
	
	def __init__(self):
		# Get config from the configfile, and if the config is not valid,
		#   just set it to be "first"
		self.msgsource = Config.get("update", "ruleMessageSource")
		if(self.msgsource != "sidmsg" and self.msgsource != "rule"):
			self.msgsource = "first"
		
		# Initialize the dictionaries to store the data in.
		self.generators = {}
		self.ruleSets = {}
		self.rules = {}
		self.classes = {}
		self.references = {}
		self.referenceTypes = {}
		self.suppress = {}
		self.filters = {}
		
	def addGenerator(self, gid, alertID = 1, message = ""):
		"""
		Adds the definition of a generator.
			
		Required parametres:
			gid			int			Generator ID	
			alertID		int
			message		string
		"""
		
		# Validate the datatypes
		if(type(gid) != int):
			raise TypeError("GeneratorID needs to be an integer")
		if(type(alertID) != int):
			raise TypeError("alertID needs to be an integer")
		if(type(message) != str):
			raise TypeError("message needs to be a string")
		
		# Add the generator to the data-structure. If a generator with the
		# same gid-alertID exists, it will simply be overwritten.
		key = "%d-%d" % (gid, alertID) 
		self.generators[key] = [self.RAW, (gid, alertID, message)]
	
	def addRule(self, sid, rev, raw, message, active, ruleset, classtype, priority = None, gid = 1):
		"""
		Adds a rule to be updated.
			
		Required parametres:
			sid			int			Signature ID
			rev			int			Revision ID
			raw			string		The raw rulestring
			message		string		AlertMessage
			active		boolean		RuleEnabled
			ruleset		string		ruleset name.
			classtype	string		Classtype name.
			
		Optional parametres:	
			priority	int			Priority
			gid			int			Generator ID
		"""
		
		# Validate the datatypes
		if(type(sid) != int):
			raise TypeError("SignatureID needs to be an integer")
		if(type(rev) != int):
			raise TypeError("Revision needs to be an integer")
		if(type(raw) != str):
			raise TypeError("raw needs to be a string")
		if(type(message) != str):
			raise TypeError("message needs to be a string")
		if(type(active) != bool):
			raise TypeError("active needs to be a bool")
		if(type(ruleset) != str):
			raise TypeError("ruleset needs to be a string")
		if(type(classtype) != str):
			raise TypeError("classtype needs to be a string")
		if(priority != None and type(priority) != int):
			raise TypeError("priority needs to be an integer")
		if(type(gid) != int):
			raise TypeError("GeneratorID needs to be an integer")
		
		# If there is no rule recieved yet with this SID, just save it.
		if(sid not in self.rules):
			self.rules[sid] = [self.RAW, (sid, rev, raw, message, active, ruleset, classtype, 
						priority, gid)]
		
		# If a rule with the same SID already exists (it might be just a message):
		else:
			# Determine which of the message-strings we are going to use. 
			if(self.msgsource == "sidmsg"):
				if(self.rules[sid][0] == self.RAW):
					msg = self.rules[sid][1][3]
				else:
					msg = self.rules[sid][1].msg
			else:
				msg = message	
			
			# Add the rule to the data-structure.
			self.rules[sid] = [self.RAW, (sid, rev, raw, msg, active, ruleset, classtype, 
						priority, gid)]
	
	def addMessage(self, sid, message):
		"""
		Updates the message of a rule.
		
		Required parametres:
			sid			int			Signature ID
			message		string		The message to be updated to.
		"""
		
		# Validate the datatypes
		if(type(sid) != int):
			raise TypeError("SignatureID needs to be an integer")
		if(type(message) != str):
			raise TypeError("message needs to be a string")
		
		# Either create an empty rule, where we add the message.
		if(sid not in self.rules):
			self.rules[sid] = [self.RAW, (sid, None, None, message, None, None, 
							None, None, None)]
		
		# Or, if the config says that sidmsg should be the message-source, update the
		# existing rule.
		elif(self.msgsource == "sidmsg"):
			rule = self.rules[sid][1]
			if(self.rules[sid][0] == self.RAW):
				self.rules[sid] = [self.RAW, (sid, rule[1], rule[2], message, rule[4], 
							rule[5], rule[6], rule[7], rule[8])]
			else:
				rev = rule.getCurrentRevision()
				self.rules[sid] = [self.RAW, (sid, rev.rev, rev.raw, message, rule.active, 
							rule.ruleSet.name, rule.ruleClass.classtype, rule.priority, 
							rule.generator.gid)]
	
	def addClass(self, classtype, description, priority):
		"""
		Adds a class to be updated
			
		Required parametres:
			classtype	string		Name of the ruleClass
			description	string		
			priority	int
		"""
		
		if(type(classtype) != str):
			raise TypeError("classtype needs to be a string")
		if(type(description) != str):
			raise TypeError("description needs to be a string")
		if(type(priority) != int):
			raise TypeError("priority needs to be an integer")

		self.classes[classtype] = [self.RAW, (classtype, description, priority)]
	
	def addReferenceType(self, name, urlPrefix):
		"""
		Adds a reference-type.
			
		Required parametres:
			name		string		The name og the reference-type
			urlPrefix	string		The prefix of the url's referenced from this
									references of this type.	
		"""
		
		if(type(name) != str):
			raise TypeError("name needs to be a string")
		if(type(urlPrefix) != str):
			raise TypeError("urlPrefix needs to be a string")
		
		self.referenceTypes[name] = [self.RAW, (name, urlPrefix)]
	
	def addReference(self, referenceType, reference, sid):
		"""
		Adds a reference to a rule.
		
		Required parametres:
			referenceType	string	The name of the reference-type.
			reference		string	Content of the reference
			sid				int		ID of the rule this reference belongs to.
		"""
		
		if(type(referenceType) != str):
			raise TypeError("referenceType needs to be a string")
		if(type(reference) != str):
			raise TypeError("reference needs to be a string")
		if(type(sid) != int):
			raise TypeError("sid needs to be an integer")

		key = "%s-%s-%d" % (referenceType, reference, sid)
		self.references[key] = [self.RAW, (referenceType, reference, sid)]
	
	def addRuleSet(self, name):
		"""
		Adds a ruleSet.
		
		Required parametres:
			name			string	The name of the ruleSet.
		"""
		
		if(type(name) != str):
			raise TypeError("name needs to be a string")

		self.ruleSets[name] = [self.RAW, name]
	
	def addSuppress(self, sid, track = None, addresses = None, gid = 1):
		"""
		Adds a suppression to a rule.
		
		Required parametres:
			sid				int		Signature ID
			
		Optional parametres:	
			track			string		Track by which addresses	(by_src|by_dst)
			addresses		[string]	Which addresses to track
			gid				int			ID of the generator to suppress. Default: 1
		"""
		
		# Verifies that the arguments make sense.
		if(type(sid) != int):
			raise TypeError("sid needs to be an integer")
		if(track not in [None, "by_src", "by_dst"]):
			raise TypeError("track needs to be by_src or by_dst")
		if(addresses and type(addresses) != list):
			raise TypeError("addresses should be a list.")
		if(addresses):
			for element in addresses:
				if(type(element) != str):
					raise TypeError("The elements in addresses should be strings.")
		if(type(gid) != int):
			raise TypeError("The GeneratorID needs to be an int.")

		# Save the suppress to memory.
		self.suppress[sid] = [self.RAW, (sid, track, addresses, gid)]
	
	def addFilter(self, sid, track, count, second, filterType = None, gid = 1):
		"""
		Adds a filter to a rule.
		
		Required parametres:
			sid			int			Signature ID
			track		string		Track by which addresses	(by_src|by_dst)
			count		int
			second		int

		Optional parametres:
			filterType	string		Which type is this filter? (limit, threshold, both, None)
										(None means that the filter is a Detection Filter.
										otherwise, it is an EventFilter).
			gid			int			Generator ID, if this filter is for a rule with another 
										generator than 1.
		"""
		
		# Validate the parametres.
		if(type(sid) != int):
			raise TypeError("SID needs to be an int")
		if(track not in ["by_src", "by_dst"]):
			raise TypeError("track needs to be either \"by_src\" or \"by_dst\"")
		if(type(count) != int):
			raise TypeError("count needs to be an int")
		if(type(second) != int):
			raise TypeError("Second needs to be an int")
		if(filterType not in [None, "limit", "threshold", "both"]):
			raise TypeError("Invalid data passed as filterType")
		if(type(gid) != int):
			raise TypeError("GeneratorID needs to be an int.")
			
		# Generate a key which helps us keep up to one filter of each type.
		if filterType:
			key = "EF-%d" % sid
		else:
			key = "DF-%d" % sid
		
		# Save the parametres to memory.
		self.filters[key] = [self.RAW, (sid, track, count, second, filterType, gid)]
	
	def saveGenerators(self):
		"""Saves all the new/changed generators to the dabase, while trying to
		minimize the impact on DB performance."""
		logger = logging.getLogger(__name__)
		
		# Analyze the retrieved generators, and create list of all the generators
		# we would need to try to fetch from the database.
		newGenerators = {}
		rawGid = []
		rawAlertID = []
		for gen in self.generators:
			if self.generators[gen][0] == self.RAW:
				newGenerators[gen] = self.generators[gen][1]
				rawGid.append(self.generators[gen][1][0])
				rawAlertID.append(self.generators[gen][1][1])
		
		logger.debug("Found %d new generators to be checked" % len(rawGid))
		
		# Try to fetch the generators from the database, and loop trough them:
		generators = Generator.objects.filter(GID__in = rawGid, alertID__in = rawAlertID).all()
		for generator in generators:
			key = "%d-%d" % (generator.GID, generator.alertID)
			# If this is a generator that we want to look at (as we will also get 1-2 when we
			#   look for 1-1 and 2-2... )
			if key in newGenerators:
				status = self.SAVED
				rawGenerator = newGenerators.pop(key)
				
				# If the message is new, add the new message.
				if(rawGenerator[2] != generator.message):
					status = self.CHANGED
					generator.message = rawGenerator[2]
				
				# If anything needed to be changed, save the object.
				if(status == self.CHANGED):
					generator.save()
					status = self.SAVED
					logger.debug("Updated %s" % str(generator))

				# Store the object in the local cache, in case it is needed later.
				self.generators[key] = [status, generator]
		
		# If there are any generators we could not find in the database
		if(len(newGenerators)):
			# Make a list of new Generator objects, a list of gid's and a list of alertID's.
			g = []
			gids = []
			alertIDs = []
			for gen in newGenerators:
				generator = newGenerators[gen]
				gids.append(generator[0])
				alertIDs.append(generator[1])
				g.append(Generator(GID=generator[0], alertID=generator[1], message=generator[2]))
			
			# Insert the created Generator objects to the database.
			Generator.objects.bulk_create(g)	
			logger.debug("Created %d new generators" % len(g))
			
			# Read them back out, and store them in memory. In case somebody needs them later in the
			# update.
			for generator in Generator.objects.filter(GID__in = gids, alertID__in = alertIDs).all():
				key = "%d-%d" % (generator.GID, generator.alertID)
				self.generators[key] = [self.SAVED, generator]
	
	def debug(self):
		""" Simple debug-method dumping all the data to stdout. """
		for l in [self.generators, self.ruleSets, self.rules, self.classes, self.references,
				self.referenceTypes, self.suppress, self.filters]:
			print "Start:"
			for element in l:
				print " - ", l[element]
