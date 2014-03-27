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

from data.files import ConfigGenerator
from data.models import Session, RuleClass, Generator, RuleReferenceType, Rule, EventFilter, Suppress

def main():
	logger = logging.getLogger(__name__)
	
	generator = ConfigGenerator()
	s = Session.session()

	generator.generateConfigFile("classification.config", s.query(RuleClass).all(), lambda x: "config classification: %s,%s,%d" % (x.classtype, x.description, int(x.priority)))
	generator.generateConfigFile("gen-msg.map", s.query(Generator).order_by(Generator.gid).order_by(Generator.alertId).all(), lambda x: "%d || %d || %s" % (x.gid, x.alertId, x.message))
	generator.generateConfigFile("reference.config", s.query(RuleReferenceType).all(), lambda x: "config reference: %s %s" % (x.name, x.prefix))
	generator.generateRuleFiles()
	generator.generateConfigFile("suppress.config", s.query(Suppress).all(), lambda x: x.getConfigString())
	generator.generateConfigFile("eventfilters.config", s.query(EventFilter).all(), 
			lambda x: "event_filter gen_id 1, sig_id %d, type %s, track %s, count %d, seconds %s" % (x.rule.SID, EventFilter.TYPE[x.filtertype], EventFilter.TRACK[x.track], x.count, x.seconds))
	generator.generateIncludes()
	
if __name__ == "__main__":
	main()
