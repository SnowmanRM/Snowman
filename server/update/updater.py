#!/usr/bin/python
"""
update.updater.Updater

The updater module is responsible to recieve the parsed rules, and store them in the database.
It will raise an TypeError if any of the data is of wrong types..
"""

import logging

from core.models import Generator, Rule, RuleRevision, RuleSet, RuleClass, RuleReference, RuleReferenceType
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
	
	def addFilter(self, sid, track, count, seconds, filterType = None, gid = 1):
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
		if(type(seconds) != int):
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
		self.filters[key] = [self.RAW, (sid, track, count, seconds, filterType, gid)]
	
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
	
	def saveClasses(self):
		"""Saves all the new/changed ruleclasses to the dabase, while trying to
		minimize the impact on DB performance."""
		logger = logging.getLogger(__name__)
		
		# Analyze the retrieved classes, and create list of all the classes
		# we would need to try to fetch from the database.
		newClasses = {}
		classnames = []
		for c in self.classes:
			if self.classes[c][0] == self.RAW:
				newClasses[c] = self.classes[c][1]
				classnames.append(self.classes[c][1][0])
		
		logger.debug("Found %d new classes to be checked" % len(classnames))
		
		# Try to fetch the classtypes from the database, and loop trough them:
		classes = RuleClass.objects.filter(classtype__in = classnames).all()
		for c in classes:
			status = self.SAVED
			raw = newClasses.pop(c.classtype)
			
			# If any of the parametres have changed, update them, and set the
			# status-flag to changed
			if(raw[1] != c.description):
				status = self.CHANGED
				c.description = raw[1]
			if(raw[2] != c.priority):
				status = self.CHANGED
				c.priority = raw[2]
			
			# If anything needed to be changed, save the object.
			if(status == self.CHANGED):
				c.save()
				status = self.SAVED
				logger.debug("Updated %s" % str(c))

			# Store the object in the local cache, in case it is needed later.
			self.classes[c.classtype] = [status, c]
		
		if(len(newClasses)):
			# Make a list of new RuleClass objects, and a list of classtypes..
			ruleClasses = []
			classtypes = []
			for c in newClasses:
				classtypes.append(newClasses[c][0])
				ruleClasses.append(RuleClass(classtype=newClasses[c][0], description=newClasses[c][1], priority=newClasses[c][2]))
			
			# Insert the created RuleClass objects to the database.
			RuleClass.objects.bulk_create(ruleClasses)	
			logger.debug("Created %d new RuleClass-es" % len(ruleClasses))
			
			# Read them back out, and store them in memory. In case somebody needs them later in the
			# update.
			for classtype in RuleClass.objects.filter(classtype__in=classtypes).all():
				self.classes[classtype.classtype] = [self.SAVED, classtype]
	
	def saveReferenceTypes(self):
		"""Saves all the new/changed RuleReferenceType's to the dabase, while trying to
		minimize the impact on DB performance."""
		logger = logging.getLogger(__name__)
		
		# Analyze the retrieved referencetypes, and create list of all the types
		# we would need to try to fetch from the database.
		newTypes = {}
		typenames = []
		for refType in self.referenceTypes:
			if self.referenceTypes[refType][0] == self.RAW:
				newTypes[refType] = self.referenceTypes[refType][1]
				typenames.append(self.referenceTypes[refType][1][0])
		
		logger.debug("Found %d new RuleReferenceType's to be checked" % len(newTypes))
		
		# Try to fetch the referenceType from the database, and loop trough them:
		refTypes = RuleReferenceType.objects.filter(name__in=typenames).all()
		for t in refTypes:
			status = self.SAVED
			raw = newTypes.pop(t.name)
			
			# If any of the parametres have changed, update them, and set the
			# status-flag to changed
			if(raw[1] != t.urlPrefix):
				t.urlPrefix = raw[1]
				t.save()
				status = self.SAVED
				logger.debug("Updated %s" % str(t))

			# Store the object in the local cache, in case it is needed later.
			self.referenceTypes[t.name] = [status, t]
		
		if(len(newTypes)):
			# Make a list of new RuleReferenceType objects, and a list of their names.
			refTypes = []
			typeNames = []
			for t in newTypes:
				typeNames.append(newTypes[t][0])
				refTypes.append(RuleReferenceType(name=newTypes[t][0], urlPrefix=newTypes[t][1]))
			
			# Insert the created RuleReferenceType objects to the database.
			RuleReferenceType.objects.bulk_create(refTypes)	
			logger.debug("Created %d new RuleReferenceType's" % len(refTypes))
			
			# Read them back out, and store them in memory. In case somebody needs them later in the
			# update.
			for refType in RuleReferenceType.objects.filter(name__in=typeNames).all():
				self.referenceTypes[refType.name] = [self.SAVED, refType]
			
	def saveRuleSets(self):
		"""Saves all the new/changed RuleSet's to the dabase, while trying to
		minimize the impact on DB performance."""
		logger = logging.getLogger(__name__)
		
		# Analyze the retrieved sets, and create list of all the sets
		# we would need to try to fetch from the database.
		newSets = []
		for ruleSet in self.ruleSets:
			if self.ruleSets[ruleSet][0] == self.RAW:
				newSets.append(ruleSet)
		
		logger.debug("Found %d new RuleSet's to be checked" % len(newSets))
		
		# Try to fetch the referenceType from the database, and loop trough them:
		sets = RuleSet.objects.filter(name__in=newSets).all()
		for s in sets:
			status = self.SAVED
			newSets.remove(s.name)
			self.ruleSets[s.name] = [status, s]
		
		if(len(newSets)):
			# Make a list of new RuleSet objects.
			ruleSets = []
			for s in newSets:
				ruleSets.append(RuleSet(name=s, active=True, description=s))
			
			# Insert the created RuleReferenceType objects to the database.
			RuleSet.objects.bulk_create(ruleSets)	
			logger.debug("Created %d new RuleSet's" % len(ruleSets))
			
			# Read them back out, and store them in memory. In case somebody needs them later in the
			# update.
			for ruleSet in RuleSet.objects.filter(name__in=newSets).all():
				self.ruleSets[ruleSet.name] = [self.SAVED, ruleSet]
	
	def saveRules(self):
		"""Saves the rules recieved"""
		logger = logging.getLogger(__name__)

		# Create a list of rule's SID
		sids = []
		newRules = {}
		for rule in self.rules:
			if(self.rules[rule][0] == self.RAW):
				sids.append(self.rules[rule][1][0])
				newRules[self.rules[rule][1][0]] = self.rules[rule][1]
		
		# Collect a list of the SID/rev pairs matching any SID we currently have the rule in RAW format.
		revisionids = RuleRevision.objects.filter(rule__SID__in = sids).values_list("pk", flat=True).distinct()
		sidrev = RuleRevision.objects.filter(pk__in=revisionids).values_list("rule__SID", "rev").all()
		
		# Compare the SID/rev of all new Rules with the results from the database, and determine which rules
		# really is new, and which rules are updated, and which have no changes. (We still skip looking at
		# rules where the SID/rev values is seen before.)
		updated = {}
		unchanged = {}
		for sid, rev in sidrev:
			if(sid in newRules):
				raw = newRules.pop(sid)
				if(raw[1] > rev):
					updated[sid] = raw
				else:
					unchanged[sid] = raw
		
		# Create new revisions to all the rules that needs an update.
		activateNewRevisions = (Config.get("update", "activateNewRevisions") == "true")
		changeRuleSet = (Config.get("update", "changeRuleset") == "true")
		newRevisions = []
		for rule in Rule.objects.filter(SID__in=updated.keys()).select_related('ruleSet', 'ruleClass').all():
			status = self.SAVED
			raw = updated[rule.SID]

			# Create a new rule-revision.
			newRevisions.append(RuleRevision(rule=rule, rev=raw[1], msg=raw[3], raw=raw[2], active=activateNewRevisions))
			
			# Update ruleset and/or classification if they have changed:
			if(rule.ruleSet.name != raw[5]):
				if(changeRuleSet):
					status = self.CHANGED
					rule.ruleSet = self.ruleSets[raw[5]][1]
				#TODO: Create RuleChange objects.
			if(rule.ruleClass.name != raw[6]):
				status = self.CHANGED
				rule.ruleClass = self.classes[raw[6]][1]

			# Update various other parametres if they are changed:
			if(rule.active != raw[4]):
				status = self.CHANGED
				rule.active = raw[4]
			if(rule.priority != raw[7]):
				status = self.CHANGED
				rule.priority = raw[7]
			if(rule.generator_id != raw[8]):
				status = self.CHANGED
				rule.generator_id = raw[8]
				
			# If anything is saved in the Rule-object, save it:
			if(status == self.CHANGED):
				logger.debug("Updated %s" % str(rule))
				rule.save()
				self.rules[rule.SID] = [self.SAVED, rule]
			
		# Create new Rule objects for all the new rules
		newRuleObjects = []
		for sid in newRules:
			newRuleObjects.append(Rule(SID=sid, active=(activateNewRevisions and newRules[sid][4]), 
					ruleSet=self.ruleSets[newRules[sid][5]][1], ruleClass=self.classes[newRules[sid][6]][1],
					priority=newRules[sid][7], generator_id=newRules[sid][8]))
		Rule.objects.bulk_create(newRuleObjects)
		logger.debug("Created %d new Rule's" % len(newRuleObjects))
		
		for rule in Rule.objects.filter(SID__in=newRules.keys()).all():
			raw = newRules[rule.SID]
			self.rules[rule.SID] = [self.SAVED, rule]
			newRevisions.append(RuleRevision(rule=rule, rev=raw[1], msg=raw[3], raw=raw[2], active=activateNewRevisions))
		
		# Store the new revisions to the database
		RuleRevision.objects.bulk_create(newRevisions)
		logger.debug("Created %d new RuleRevision's" % len(newRevisions))

		# If the config states so, retrieve the rule-objects of all the rules that have not been changed yet.
		if(Config.get("update", "cacheUnchangedRules") == "true"):
			for rule in Rule.objects.filter(SID__in=unchanged.keys()).all():
				self.rules[rule.SID] = [self.SAVED, rule]
			
	def saveReferences(self):
		#self.references[key] = [self.RAW, (referenceType, reference, sid)]
		pass
	
	def saveSuppress(self):
		#self.suppress[sid] = [self.RAW, (sid, track, addresses, gid)]
		pass
	
	def saveFilters(self):
		#self.filters[key] = [self.RAW, (sid, track, count, second, filterType, gid)]
		pass
		
	def saveAll(self):
		self.saveGenerators()
		self.saveClasses()
		self.saveReferenceTypes()
		self.saveRuleSets()
		self.saveRules()
	
	def debug(self):
		""" Simple debug-method dumping all the data to stdout. """
		for l in [self.generators, self.ruleSets, self.rules, self.classes, self.references,
				self.referenceTypes, self.suppress, self.filters]:
			print "Start:"
			for element in l:
				print " - ", l[element]
