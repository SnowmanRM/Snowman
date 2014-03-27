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

# Initialize the logger
from util.logger import initialize
initialize()

from data.models import Session, Rule, RuleSet, RuleClass
from data.sync import SnowmanServer
from util.config import Config

def main():
	logger = logging.getLogger(__name__)

	server = SnowmanServer()
	
	if server.connect():
		server.synchronizeClasses()
		server.synchronizeGenerators()
		server.synchronizeRuleReferenceTypes()
		server.synchronizeRuleSets()
		server.synchronizeRules()
	
		server.disconnect()
	else:
		print "Could not connect to snowman server."

if __name__ == "__main__":
	main()
