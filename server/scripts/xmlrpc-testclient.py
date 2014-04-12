#!/usr/bin/python
import os
import sys
import xmlrpclib

# Add the parent folder of the script to the path
scriptpath = os.path.realpath(__file__)
scriptdir = os.path.dirname(scriptpath)
parentdir = os.path.dirname(scriptdir)
sys.path.append(parentdir)

# Tell where to find the DJANGO settings.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "srm.settings")

from util.config import Config

server = xmlrpclib.Server('https://' + Config.get("xmlrpc-server", "address") + ":" + Config.get("xmlrpc-server","port"))

print server.ping()
print server.dummy("ABC")
print server.getList()
print server.getDict()
