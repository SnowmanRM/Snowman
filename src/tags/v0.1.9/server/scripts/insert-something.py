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

if __name__ == "__main__":
    from update.models import Update
    from util.logger import initialize
    
    if(len(sys.argv) < 2):
        print "Usage: %s <file>"
        sys.exit(1)

    initialize()
    logger = logging.getLogger(__name__)
    logger.info("Starting test-script")
    
    u = Update.objects.first()
    u.parseSidMsgFile(sys.argv[1])
    
    logger.info("Finishing test-script")
