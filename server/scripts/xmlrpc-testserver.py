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
from util.xmlrpcserver import RPCServer
from util.config import Config

class RPCInterface():
	def __init__(self):
		import string
		self.python_string = string
	
	def ping(self):
		return "Pong!"
	
	def dummy(self, data):
		return str(type(data)) + ":" + str(data)
	
	def getList(self):
		return ['ABC', 'DEF', 'GHI', 'JKL', 'MNO']
	
	def getDict(self):
		return {'En':1, 'To':2, 'Tre':3}

def startRPCServer():
	bindAddress = Config.get("xmlrpc-server", "address")
	bindPort = int(Config.get("xmlrpc-server", "port"))
	
	server_address = (bindAddress, bindPort) # (address, port)
	server = RPCServer(RPCInterface(), server_address)	
	sa = server.socket.getsockname()

	print "Serving HTTPS on", sa[0], "port", sa[1]
	server.startup()

if __name__ == '__main__':
	startRPCServer()
