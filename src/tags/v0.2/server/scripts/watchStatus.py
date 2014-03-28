#!/usr/bin/python
import os
import sys

# To let a standalone-script use Django, you need to add the path for the root-directory
# of our project to the sys-path. For this script, that is the parent folder, of the folder
# this script is in.
scriptpath = os.path.realpath(__file__)
scriptdir = os.path.dirname(scriptpath)
parentdir = os.path.dirname(scriptdir)
sys.path.append(parentdir)

# Tell where to find the DJANGO settings.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "srm.settings")

# Start using django
from update.models import Source, Update, UpdateLog

updates = Update.objects.order_by('time').all()
for update in updates:
	print update
	for logentry in update.logEntries.all():
		print " - ", logentry
