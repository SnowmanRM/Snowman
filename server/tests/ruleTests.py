'''
Created on Mar 13, 2014

@author: echo
'''
import unittest, datetime
from core.models import Rule
from update.models import Update, Source


class Test(unittest.TestCase):


	def setUp(self):
		# Create source and update objects
		try:
			source = Source.objects.get(name="Manual")
		except Source.DoesNotExist:
			source = Source.objects.create(name="Manual", schedule="00:00", url="", lastMd5="")
	
		self.update = Update.objects.create(time=datetime.datetime.now(), source=source)


	def tearDown(self):
		pass


	def testReferences(self):
		rulestring = 'alert tcp any any -> any 21 (\
						msg:"IDS287/ftp-wuftp260-venglin-linux"; \
						reference:arachnids,IDS287; reference:arachnids,IDS287; reference:bugtraq,1387; reference:cve,CAN-2000-1574;\
						classtype: example-classtype; sid:2000000; rev:1)'
		rule = self.update.updateRule(rulestring,"testfile.rules")
		rule.delete()
		
		


if __name__ == "__main__":
	#import sys;sys.argv = ['', 'Test.testName']
	unittest.main()