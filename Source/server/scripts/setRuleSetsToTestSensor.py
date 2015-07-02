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

rulesets = RuleSet.objects.all()
sensor = Sensor.objects.get(name="Test")

sensor.ruleSets = rulesets
sensor.save()
print sensor.requestUpdate()
