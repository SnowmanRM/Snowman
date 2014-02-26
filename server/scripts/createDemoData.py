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

from django.contrib.auth.models import User

from core.models import *


# User for the sensor we are going to create later..
user = User.objects.create(username = "MySensor1", first_name = "MySensor", last_name = "1")
user.set_password("123")
user.save()

user2 = User.objects.create(username = "MySensor2", first_name = "MySensor", last_name = "2")
user2.set_password("123")
user2.save()

user3 = User.objects.create(username = "MySensor3", first_name = "MySensor", last_name = "3")
user3.set_password("123")
user3.save()

# Data for core
sensor = Sensor.objects.create(name="MySensor1", user=user, active=True, ipAddress="127.0.0.1")
sensor = Sensor.objects.create(name="MySensor2", user=user2, active=True, ipAddress="127.0.0.2")
sensor = Sensor.objects.create(name="MySensor3", user=user3, active=True, ipAddress="127.0.0.3")

