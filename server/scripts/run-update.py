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
from util.logger import initialize

if __name__ == "__main__":
    
    if(len(sys.argv) < 2):
        print "Usage: %s <rulefile>"
        sys.exit(1)
        
    sourceFolder = sys.argv[1]

    initialize()
    logger = logging.getLogger(__name__)
    logger.info("Starting run-update-script")
    
    
    # Create source and update objects
    source = Source.objects.create(name="Manual", schedule="00:00", url="", lastMd5="")
    update = Update.objects.create(time="2014-01-01", source=source)
    
    # 1. Read and update the classifications
    # 2. Read and update the generators
    print "Parsing classifications..."
    update.parseClassificationFile(sourceFolder+"/etc/classification.config")
    print "Parsing gen-msg..."
    update.parseGenMsgFile(sourceFolder+"/etc/gen-msg.map")
    print "Parsing reference..."
    update.parseReferenceConfig(sourceFolder+"/etc/reference.config")
    print "Parsing rules..."
    
    for filename in os.listdir(sourceFolder+"/rules"):
        if filename.endswith(".rules"):
            print "Parsing file "+filename
            update.parseRuleFile(sourceFolder+"/rules/"+filename)
            
    print "Parsing sid-msg..."
    
    update.parseSidMsgFile(sourceFolder+"/etc/sid-msg.map")
    
    print "Done!"
    