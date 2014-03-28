#!/usr/bin/python
import os
import sys
import xmlrpclib
import logging
import socket

# Add the parent folder of the script to the path
scriptpath = os.path.realpath(__file__)
scriptdir = os.path.dirname(scriptpath)
parentdir = os.path.dirname(scriptdir)
sys.path.append(parentdir)

from util.logger import initialize
initialize()

from data.models import Session, Rule, RuleSet, RuleClass
from util.config import Config

def synchronizeClasses(xmlrpcserver):
	logger = logging.getLogger(__name__)
	logger.info("Starting RuleClass synchronization")
	s = Session.session()

	serverRuleClasses = xmlrpcserver.getRuleClasses()
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

def synchronizeRuleSets(xmlrpcserver):
	logger = logging.getLogger(__name__)
	logger.info("Starting to synchronize RuleSets")
	s = Session.session()
	
	serverSets = xmlrpcserver.getRuleSets()
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
	
def synchronizeRules(xmlrpcserver):
	logger = logging.getLogger(__name__)
	maxRuleRequests = int(Config.get("sync", "maxRulesInRequest"))

	s = Session.session()
	
	logger.info("Starting to synchronize the Rules")
	logger.debug("Collecting the SID/rev pairs from the server")
	
	rulerevisions = xmlrpcserver.getRuleRevisions()
	
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
	
	rulerevisions = list(rulerevisions)
	while len(rulerevisions) > 0:
		request = rulerevisions[:maxRuleRequests]
		logger.debug("Requesting %d out of %d rules" % (len(request), len(rulerevisions)))
		
		rules = xmlrpcserver.getRules(request)
		
		for r in rules:
			rule = Rule(sid=rules[r]['SID'], rev=rules[r]['rev'], msg=rules[r]['msg'], raw=rules[r]['raw'])	
			rule.ruleset = ruleSets[rules[r]['ruleset']]
			rule.ruleclass = ruleClasses[rules[r]['ruleclass']]
			s.add(rule)
			logger.debug("Got a new rule from the server: " + str(rule))
			rulerevisions.remove(r)
		s.commit()
	
	logger.info("Finished synchronizing the rules from the server")
		

def main():
	logger = logging.getLogger(__name__)

	logger.info("Connecting to the SRM-Server")
	try:
		server = xmlrpclib.Server('https://' + Config.get("srm-server", "address") + ":" + Config.get("srm-server","port"))

		synchronizeClasses(server)
		synchronizeRuleSets(server)
		synchronizeRules(server)
	except socket.error as e:
		print "Could not connect to srm-server:", e
		logger.error("Could not connect!")
		logger.error(str(e))
		sys.exit(1)

if __name__ == "__main__":
	main()
