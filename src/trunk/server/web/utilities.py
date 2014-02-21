#!/usr/bin/python

class UserSettings():
	DEFAULT = 0
	RULELIST = 1
	
	@staticmethod
	def getPageLength(request, pagetype = 0):
		return 10
