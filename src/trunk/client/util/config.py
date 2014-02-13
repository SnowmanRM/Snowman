#!/usr/bin/python
from ConfigParser import ConfigParser

class Config:
	"""A very simple configuration class for the SRM client. It relies heavily on the
	ConfigParser from python, and makes the method get easily accessible.

	To get a parameter from the configfiles, you can use the method: Config.get("section", "Variable")"""

	parser = None
	get = None
	
	@staticmethod
	def initialize():
		"""Initializes the configparser. Reads the configfiles, and puts their content
		into a ConfigParser object."""
		configfiles = ["settings.cfg"]
		Config.parser = ConfigParser()
		Config.parser.read(configfiles)
		Config.get = Config.parser.get

# Makes sure that the configparser is initialized when a module is included.
if(Config.parser == None):
	Config.initialize()
