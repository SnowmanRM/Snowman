#!/usr/bin/python
import os
import sys
import xmlrpclib
import logging
import socket

from util.logger import initialize

from data.models import Session, Rule, RuleSet, RuleClass, RuleReference, RuleReferenceType, Generator, EventFilter, DetectionFilter, Suppress, SuppressAddress
from util.config import Config

class SnowmanServer:
	"""This class is responsible for the communication with the central snowman server.
	It connects, authenticates and maintains the connection while the synchronizations are
	running."""

	class ConnectionError(Exception):
		"""Exception which is raised when anything regarding the connection to the central server fails."""
		def __init__(self, message):
			Exception.__init__(self, message)
	
	def __init__(self):
		self.server = None
		self.connected = False
		self.token = None
		self.id = None

	def connect(self):
		"""Method which tries to connect to the central snowman-server, and authenticate with it.
		SnowmanServer.ConnectionError is thrown if the server is unreachable.
		
		returns True if successfully authenticated, False othervise."""

		logger = logging.getLogger(__name__)
		logger.info("Connecting to the SRM-Server")

		# Grab configuration from configfile
		serveraddress = "https://" + Config.get("srm-server", "address") + ":" + Config.get("srm-server","port")
		self.sensorname = Config.get("general", "sensorname")
		self.secret = Config.get("general", "secret")
		
		# Try to connect and authenticate with the server. If a socket error happens, the
		#   server is considered unreachable.
		try:
			self.server = xmlrpclib.Server(serveraddress)
			response = self.server.authenticate(self.sensorname, self.secret)
		except socket.error as e:
			logger.error("Could not connect to %s!" % serveraddress)
			logger.error(str(e))
			raise SnowmanServer.ConnectionError("Could not connect to %s!" % serveraddress)
		
		# If the server-response is positive, save the session-info before returning True to caller.
		if(response['status']):
			self.connected = True
			self.token = response['token']
			self.id = response['sensorID']
			logger.info("Successfully authenticated with the server")
			return True
		
		# If the authentication failed, log the error-message befor False is returned.
		else:
			self.connected = False
			logger.info("Could not connect to snowman-server. The server states: %s" % response['message'])
			return False
	
	def disconnect(self):
		"""Method which tries to deauthenticate from the server.
		When successfull, all the cached session-info is cleared, and the server invalidates the token."""

		logger = logging.getLogger(__name__)
		
		# Try to send a deauthentication-message to the server, so that it can clear its cache.
		try:
			response = self.server.deAuthenticate(self.token)
		except socket.error as e:
			logger.error("Could not connect to %s!" % serveraddress)
			logger.error(str(e))
			raise SnowmanServer.ConnectionError("Error in the connection to %s!" % serveraddress)
		
		# If successfull, clear the session-info.
		if(response['status']):
			self.server = None
			self.connected = False
			self.token = None
			self.id = None
			logger.info("Disconnected from the snowman-server.")
		
	def synchronizeGenerators(self):
		logger = logging.getLogger(__name__)
		logger.info("Starting Generator synchronization")
		s = Session.session()
	
		try:
			response = self.server.getGenerators(self.token)
		except socket.error as e:
			logger.error("Could not connect to %s!" % serveraddress)
			logger.error(str(e))
			raise SnowmanServer.ConnectionError("Error in the connection to %s!" % serveraddress)
		
		if(response['status']):
			generators = response['generators']
		else:
			logger.error("Could not retrieve Generator from the server: %s", response['message'])
			raise SnowmanServer.ConnectionError("Could not retrieve Generator from the server.")
		
		localGenerators = {}
		for g in s.query(Generator).all():
			localGenerators[str(g.gid) + "-" + str(g.alertId)] = g
		
		i = 0
		for g in generators:
			if g not in localGenerators:
				localGenerators[g] = Generator(gid=generators[g]['GID'], alertId=generators[g]['alertID'], message=generators[g]['message'])
				s.add(localGenerators[g])
				logger.debug("Added a new generator to the local cache:" + str(localGenerators[g]))
				i += 1
			# TODO: Update generators where the servers version is different from the sensors.
			
		s.commit()
		logger.info("Imported %d new Generators from the srm-server" % i)
		
		i = 0
		for g in localGenerators:
			if g not in generators:
				logger.debug("Deleted a generator from the local cache: " + str(localGenerators[g]))
				s.delete(localGenerators[g])
				i += 1
			
		s.commit()
		logger.info("Removed %d Generators from the local cache." % i)
	
		logger.info("Synchronization of the generators is finished.")
	
	def synchronizeRuleReferenceTypes(self):
		logger = logging.getLogger(__name__)
		logger.info("Starting RuleReferenceType synchronization")
		s = Session.session()
	
		try:
			response = self.server.getReferenceTypes(self.token)
		except socket.error as e:
			logger.error("Could not connect to %s!" % serveraddress)
			logger.error(str(e))
			raise SnowmanServer.ConnectionError("Error in the connection to %s!" % serveraddress)
		
		if(response['status']):
			referenceTypes = response['referenceTypes']
		else:
			logger.error("Could not retrieve RuleReferenceTypes from the server: %s", response['message'])
			raise SnowmanServer.ConnectionError("Could not retrieve RuleReferenceType from the server.")
		
		localReferenceTypes = {}
		for e in s.query(RuleReferenceType).all():
			localReferenceTypes[str(e.name)] = e
		
		i = 0
		for r in referenceTypes:
			if r not in localReferenceTypes:
				localReferenceTypes[r] = RuleReferenceType(name=referenceTypes[r]['name'], prefix=referenceTypes[r]['urlPrefix'])
				s.add(localReferenceTypes[r])
				logger.debug("Added a new RuleReferenceType to the local cache:" + str(localReferenceTypes[r]))
				i += 1
			# TODO: Update referencetypes where the servers version is different from the sensors.
			
		s.commit()
		logger.info("Imported %d new RuleReferenceTypes from the srm-server" % i)
		
		i = 0
		for r in localReferenceTypes:
			if r not in referenceTypes:
				logger.debug("Deleted a RuleReferenceType from the local cache: " + str(localReferenceTypes[r]))
				s.delete(localReferenceTypes[r])
				i += 1
			
		s.commit()
		logger.info("Removed %d RuleReferenceTypes from the local cache." % i)
	
		logger.info("Synchronization of the RuleReferenceTypes is finished.")

	def synchronizeClasses(self):
		logger = logging.getLogger(__name__)
		logger.info("Starting RuleClass synchronization")
		s = Session.session()
	
		try:
			response = self.server.getRuleClasses(self.token)
		except socket.error as e:
			logger.error("Could not connect to %s!" % serveraddress)
			logger.error(str(e))
			raise SnowmanServer.ConnectionError("Error in the connection to %s!" % serveraddress)
		
		if(response['status']):
			serverRuleClasses = response['classes']
		else:
			logger.error("Could not retrieve RuleClasses from the server: %s", response['message'])
			raise SnowmanServer.ConnectionError("Could not retrieve RuleClasses from the server.")
		
		localRuleClasses = {}
		for rc in s.query(RuleClass).all():
			localRuleClasses[rc.classtype] = rc
		
		# Import new classes
		i = 0
		for c in serverRuleClasses:
			if c not in localRuleClasses:
				localRuleClasses[c] = RuleClass(classtype=c, description=serverRuleClasses[c]['description'], priority=serverRuleClasses[c]['priority'])
				s.add(localRuleClasses[c])
				logger.debug("Added a new ruleClass to the local cache:" + str(localRuleClasses[c]))
				i += 1
			# TODO: Update ruleclasses where the servers version is different from the sensors.
			
		s.commit()
		logger.info("Imported %d new RuleClasses from the srm-server" % i)
		
		# Delete Classes that we are not going to have anymore
		i = 0
		for c in localRuleClasses:
			if c not in serverRuleClasses:
				logger.debug("Deleted a rule-class from the local cache: " + str(localRuleClasses[c]))
				s.delete(localRuleClasses[c])
				i += 1
			
		s.commit()
		logger.info("Removed %d RuleClasses from the local cache." % i)
	
		logger.info("Synchronization of the ruleclasses is finished.")

	def synchronizeRuleSets(self):
		logger = logging.getLogger(__name__)
		logger.info("Starting to synchronize RuleSets")
		s = Session.session()
		
		try:
			response = self.server.getRuleSets(self.token)
		except socket.error as e:
			logger.error("Could not connect to %s!" % serveraddress)
			logger.error(str(e))
			raise SnowmanServer.ConnectionError("Error in the connection to %s!" % serveraddress)
		
		if(response['status']):
			serverSets = response['rulesets']
		else:
			logger.error("Could not retrieve RuleSets from the server: %s", response['message'])
			raise SnowmanServer.ConnectionError("Could not retrieve RuleSets from the server.")
		
		localSets = {}
		for rs in s.query(RuleSet).all():
			localSets[rs.name] = rs
		
		# Add the new RuleSets
		i = 0
		for rs in serverSets:
			if rs not in localSets:
				ruleSet = RuleSet(name=serverSets[rs]['name'], description=serverSets[rs]['description'])
				s.add(ruleSet)
				logger.debug("Added a new RuleSet to the local cache: " + str(ruleSet))
				i += 1
		s.commit()
		logger.info("Imported %d new RuleSets from the srm-server" % i)
		
		# Delete the rulesets that is not on the server anymore.
		i = 0
		for rs in localSets:
			if rs not in serverSets:
				s.delete(localSets[rs])
				logger.debug("Deleted a RuleSet from the local cache: " + str(localSets[rs]))
				i += 1
		s.commit()
		logger.info("Removed %d RuleSets from the local cache" % i)
	
		logger.info("RuleSet synchronization is finished.")
		
	def synchronizeRules(self):
		logger = logging.getLogger(__name__)
		maxRuleRequests = int(Config.get("sync", "maxRulesInRequest"))
	
		s = Session.session()
		
		logger.info("Starting to synchronize the Rules")
		logger.debug("Collecting the SID/rev pairs from the server")
		
		response = self.server.getRuleRevisions(self.token)
		if(response['status'] == False):
			logger.error("Could not get rulerevisions from the server: %s" % response['message'])
			raise SnowmanServer.ConnectionError("Could not retrieve RuleRevisions from the server.")
		
		rulerevisions = response['revisions']
		
		localRules = s.query(Rule).all()
		for r in localRules:
			# If the current rule is in the rulerevisions-list
			if str(r.SID) in rulerevisions and int(r.rev) == int(rulerevisions[str(r.SID)]):
				rulerevisions.pop(str(r.SID))
				logger.debug("Rule %d is already up to date" % r.SID)
			else:
				logger.debug("Rule %d is deleted, as it is going to be updated or removed." % r.SID)
				s.delete(r)
		s.commit()
		
		logger.debug("Starting to download %d rules from the server" % len(rulerevisions))
		
		ruleClasses = {}
		for rc in s.query(RuleClass).all():
			ruleClasses[rc.classtype] = rc
	
		ruleSets = {}
		for rs in s.query(RuleSet).all():
			ruleSets[rs.name] = rs
		
		reftype = {}
		for ref in s.query(RuleReferenceType).all():
			reftype[ref.name] = ref
	
		rulerevisions = list(rulerevisions)
		while len(rulerevisions) > 0:
			request = rulerevisions[:maxRuleRequests]
			logger.debug("Requesting %d out of %d rules" % (len(request), len(rulerevisions)))
			
			response = self.server.getRules(self.token, request)
			if(response['status'] == False):	
				logger.error("Could not get rulers from the server: %s" % response['message'])
				raise SnowmanServer.ConnectionError("Could not retrieve Rule from the server.")
			else:
				rules = response['rules']
			
			for r in rules:
				rule = Rule(sid=rules[r]['SID'], rev=rules[r]['rev'], msg=rules[r]['msg'], raw=rules[r]['raw'])	
				rule.ruleset = ruleSets[rules[r]['ruleset']]
				rule.ruleclass = ruleClasses[rules[r]['ruleclass']]
				s.add(rule)
				logger.debug("Got a new rule from the server: " + str(rule))

				for ref in rules[r]['references']:
					rref = RuleReference(reference=ref[1])
					rref.referenceType = reftype[ref[0]]
					rref.rule = rule
					s.add(rref)
				
				if "detectionFilter" in rules[r]:
					df = DetectionFilter(track=rules[r]['detectionFilter']['track'], count=rules[r]['detectionFilter']['count'], seconds=rules[r]['detectionFilter']['seconds'])
					df.rule = rule
					s.add(df)
				
				if "eventFilter" in rules[r]:
					ef = EventFilter(ttype=rules[r]['eventFilter']['type'], track=rules[r]['eventFilter']['track'], count=rules[r]['eventFilter']['count'], seconds=rules[r]['eventFilter']['seconds'])
					ef.rule = rule
					s.add(ef)
				
				if "suppress" in rules[r]:
					su = Suppress(track=rules[r]['suppress']['track'])
					su.rule = rule
					s.add(su)
					for address in rules[r]['suppress']['addresses']:
						sa = SuppressAddress(address)
						sa.suppress = su
						s.add(sa)
				
				rulerevisions.remove(r)
			s.commit()
		
		logger.info("Finished synchronizing the rules from the server")
