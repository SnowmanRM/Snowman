#!/usr/bin/env python
import logging
import os


if __name__ == "__main__":
	os.environ.setdefault("DJANGO_SETTINGS_MODULE", "srm.settings")
	from update.models import Update
	from util.logger import initialize
	
	initialize()
	logger = logging.getLogger(__name__)
	logger.info("Starting test-script")
	
	
	u = Update.objects.first()
	u.parseRuleFile("/tmp/snort.rules")
	
	
	logger.info("Finishing test-script")
