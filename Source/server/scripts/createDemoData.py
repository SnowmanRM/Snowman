#!/usr/bin/python
import os
import sys
import logging

# Add the parent folder of the script to the path
scriptpath = os.path.realpath(__file__)
scriptdir = os.path.dirname(scriptpath)
parentdir = os.path.dirname(scriptdir)
sys.path.append(parentdir)

# Tell where to find the DJANGO settings.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "srm.settings")
from django.contrib.auth.models import User, Group

from core.models import *
from update.models import Source
from web.models import UserProfile

logger = logging.getLogger(__name__)
logger.info("Started to create initial data.")

groupUsers, created = Group.objects.get_or_create(name="Users")
if(created):
	logger.info("Created '%s'" % groupUsers)
else:
	logger.info("'%s' already exists.", groupUsers)
groupSensors, created = Group.objects.get_or_create(name="Sensors")
if(created):
	logger.info("Created '%s'" % groupSensors)
else:
	logger.info("'%s' already exists.", groupSensors)

sensorall, created = Sensor.objects.get_or_create(name="All", user=None, active=True, autonomous=True)
user, created = User.objects.get_or_create(username="System", first_name="System", last_name="Snowman")
user, created = User.objects.get_or_create(username="srm", first_name="Demo", last_name="User")
if created:
	user.set_password("srm")
	user.groups.add(groupUsers)
	user.groups.add(groupSensors)
	user.is_staff = True
	user.save()
	profile = UserProfile.objects.create(user=user)


user, created = User.objects.get_or_create(username="Test", first_name="Test", last_name="Test")
if created:
	user.set_password("Test")
	user.groups.add(groupSensors)
	user.is_staff = False
	user.save()
	profile = UserProfile.objects.create(user=user)

sensor, created = Sensor.objects.get_or_create(name="Test", user=user, active=True, autonomous=False, parent=sensorall, ipAddress="192.168.1.100")

# Initial-data, which should always be there.
a, created = Generator.objects.get_or_create(GID=1, alertID=1, message="Generic SNORT rule")
if(created):
	logger.info("Created '%s'" % a)
else:
	logger.info("'%s' already exists.", a)

a, created = RuleReferenceType.objects.get_or_create(name = "url", urlPrefix="http://")
if(created):
	logger.info("Created '%s'" % a)
else:
	logger.info("'%s' already exists.", a)

a, created = Source.objects.get_or_create(name = "Manual")
if(created):
	logger.info("Created '%s'" % a)
else:
	logger.info("'%s' already exists.", a)

a, created = Source.objects.get_or_create(name = "SourceFire", url="http://192.168.6.11/static/rules/testset.10000-1000.tar.gz", 
		md5url="http://192.168.6.11/static/rules/testset.10000-1000.tar.gz.md5", schedule="0 1 * * *")
if(created):
	logger.info("Created '%s'" % a)
else:
	logger.info("'%s' already exists.", a)
#a, created = Source.objects.get_or_create(name = "Emerging Threats", url="http://rules.emergingthreats.net/open/snort-edge/emerging.rules.tar.gz", 
#		md5url="http://rules.emergingthreats.net/open/snort-edge/emerging.rules.tar.gz.md5", schedule="0 1 * * *")
#if(created):
#	logger.info("Created '%s'" % a)
#else:
#	logger.info("'%s' already exists.", a)
logger.info("Finished to create initial data.")
