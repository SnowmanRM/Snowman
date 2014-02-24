#!/usr/bin/env python
import logging
import os
import sys

# Add the parent folder of the script to the path
scriptpath = os.path.realpath(__file__)
scriptdir = os.path.dirname(scriptpath)
parentdir = os.path.dirname(scriptdir)
sys.path.append(parentdir)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "srm.settings")

from update.models import Update, Source
from util.logger import initConsoleLogging

if __name__ == "__main__":
    
    if(len(sys.argv) < 2):
        print "Usage: %s <update directory>"
        sys.exit(1)
        
    updateDir = sys.argv[1]

    # Init the logger
    initConsoleLogging()
    logger = logging.getLogger(__name__)
    logger.info("Starting run-update-script")
    
    # Create source and update objects
    try:
		source = Source.objects.get(name="Manual")
    except Source.DoesNotExist:
	    source = Source.objects.create(name="Manual", schedule="00:00", url="", lastMd5="")

    update = Update.objects.create(time="2014-01-01", source=source)
    
    ruleFiles = []
    classificationFile = "classification.config"
    genMsgFile = "gen-msg.map"
    referenceConfigFile = "reference.config"
    sidMsgFile = "sid-msg.map"
    
    # Walk through the directory structure and extract the absolute path
    # of all interesting files:
    for dirpath, dirnames, filenames in os.walk(updateDir):
        for ruleFile in filenames:
            if ruleFile.endswith(".rules"):
                # Save the absolute path of the rule file
                ruleFiles.append(os.path.join(dirpath, ruleFile))
            elif ruleFile == classificationFile:
                classificationFile = os.path.join(dirpath, ruleFile)
            elif ruleFile == genMsgFile:
                genMsgFile = os.path.join(dirpath, ruleFile)
            elif ruleFile == referenceConfigFile:
                referenceConfigFile = os.path.join(dirpath, ruleFile)
            elif ruleFile == sidMsgFile:
                sidMsgFile = os.path.join(dirpath, ruleFile)
    
    
    # Update must parse files in the following order:
    # 1. Read and update the classifications
    # 2. Read and update the generators
    # 3. Read and update the reference types
    # 4. Read and update the rules
    # 5. Read and update the rule messages (which includes references)
    
    update.parseClassificationFile(classificationFile)
    update.parseGenMsgFile(genMsgFile)
    update.parseReferenceConfig(referenceConfigFile)
    
    for ruleFile in ruleFiles:
        update.parseRuleFile(ruleFile)

    update.parseSidMsgFile(sidMsgFile)
    
    print "Script done!"
    
