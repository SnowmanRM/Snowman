#!/usr/bin/python
"""
update.updater

The updater module is responsible to recieve the parsed rules, and store them in the database.
"""

class Updater():
	def __init__(self):
		pass
	
	def addGenerator(self, gid, alertID = None, message = None):
		"""
		Adds the definition of a generator.
			
		Required parametres:
			gid			int			Generator ID	
			alertID		int
			message		string
		"""
		pass
	
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
		pass
	
	def addMessage(self, sid, message):
		"""
		Updates the message of a rule.
		
		Required parametres:
			sid			int			Signature ID
			message		string		The message to be updated to.
		"""
		pass
	
	def addClass(self, classtype, description, priority):
		"""
		Adds a class to be updated
			
		Required parametres:
			classtype	string		Name of the ruleClass
			description	string		
			priority	int
		"""
		pass
	
	def addReferenceType(self, name, urlPrefix):
		"""
		Adds a reference-type.
			
		Required parametres:
			name		string		The name og the reference-type
			urlPrefix	string		The prefix of the url's referenced from this
									references of this type.	
		"""
		pass
	
	def addReference(self, referenceType, reference, sid):
		"""
		Adds a reference to a rule.
		
		Required parametres:
			referenceType	string	The name of the reference-type.
			reference		string	Content of the reference
			sid				int		ID of the rule this reference belongs to.
		"""
		pass
	
	def addRuleSet(self, name):
		"""
		Adds a ruleSet.
		
		Required parametres:
			name			string	The name of the ruleSet.
		"""
		pass
	
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
		pass
	
	def addFilter(self, sid, track, count, second, filterType = None, gid = 1):
		"""
		Adds a filter to a rule.
		
		Required parametres:
			sid			int			Signature ID
			track		string		Track by which addresses	(by_src|by_dst)
			count		int
			seconds		int

		Optional parametres:
			filterType	string		Which type is this filter? (limit, threshold, both, None)
										(None means that the filter is a Detection Filter.
										otherwise, it is an EventFilter).
			gig			int			Generator ID, if this filter is for a rule with another 
										generator than 1.
		"""
		pass
