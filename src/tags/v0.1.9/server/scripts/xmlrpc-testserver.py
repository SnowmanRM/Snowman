#!/usr/bin/python
import os
import sys

# Add the parent folder of the script to the path
scriptpath = os.path.realpath(__file__)
scriptdir = os.path.dirname(scriptpath)
parentdir = os.path.dirname(scriptdir)
sys.path.append(parentdir)

# Tell where to find the DJANGO settings.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "srm.settings")
from core.models import Rule, RuleSet, RuleClass
from util.xmlrpcserver import RPCServer
from util.config import Config

class RPCInterface():
	def __init__(self):
		import string
		self.python_string = string
	
	def getRuleClasses(self):
		classes = {}
		
		for rc in RuleClass.objects.all():
			c = {}
			c['classtype'] = rc.classtype
			c['description'] = rc.description
			c['priority'] = rc.priority
			classes[rc.classtype] = c
		
		return classes
	
	def getRuleRevisions(self):
		rulelist = Rule.getRuleRevisions()
		rl = {}
		for r in rulelist:
			rl[str(r)] = rulelist[r]
		return rl
	
	def getRuleSets(self):
		rulesets = {}
		for rs in RuleSet.objects.all():
			ruleset = {}
			ruleset['name'] = rs.name
			ruleset['description'] = rs.description 
			rulesets[rs.name] = ruleset
		return rulesets
	
	def getRules(self, rulelist):
		if(len(rulelist) > 250):
			raise Exception("Cannot request more than 250 rules")
		
		rules = {}
		for r in rulelist:
			rule = Rule.objects.get(SID=r)
			dictRule = {}
			dictRule['SID'] = rule.SID
			dictRule['rev'] = rule.revisions.last().rev
			dictRule['msg'] = rule.revisions.last().msg
			dictRule['raw'] = rule.revisions.last().raw
			dictRule['ruleset'] = rule.ruleSet.name
			dictRule['ruleclass'] = rule.ruleClass.classtype
			rules[str(rule.SID)] = dictRule
		
		return rules
	
	def ping(self):
		return "Pong!"
	
	def dummy(self, data):
		return str(type(data)) + ":" + str(data)
	
	def getList(self):
		return ['ABC', 'DEF', 'GHI', 'JKL', 'MNO']
	
	def getDict(self):
		return {'En':1, 'To':2, 'Tre':3}

def startRPCServer():
	bindAddress = Config.get("xmlrpc-server", "address")
	bindPort = int(Config.get("xmlrpc-server", "port"))
	
	server_address = (bindAddress, bindPort) # (address, port)
	server = RPCServer(RPCInterface(), server_address)	
	sa = server.socket.getsockname()

	print "Serving HTTPS on", sa[0], "port", sa[1]
	server.startup()

if __name__ == '__main__':
	startRPCServer()
