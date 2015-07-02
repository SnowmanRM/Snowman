#!/usr/bin/python
import datetime

class ConfigFile:
	"""A class which helps us to keep a nice format for our configfiles. It makes sure
	to include som comments in the top of the file, together with a timestamp. This way
	it is visible from where the file is, and when it is created."""

	def __init__(self, filename):
		"""Store the filename, open a filedescriptor, and print the beginning comments 
		the file."""
		self.filename = filename
		self.file = open(self.filename, "w")
		self.file.write("# This file is automaticly created by Snowman\n")
		self.file.write("# Creationtime: %s\n\n" % str(datetime.datetime.now()))
	
	def addLine(self, line):
		"""Adds a string to the cofigfile, followed by a linebreak."""
		self.file.write("%s\n" % line)
	
	def close(self):
		"""Closes the filedescriptor."""
		self.file.close()

