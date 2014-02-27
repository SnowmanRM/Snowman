import unittest
import os
import sys
import datetime

from core.models import Generator, Rule, RuleSet, RuleRevision, RuleClass,\
	RuleReference, RuleReferenceType
	
from update.models import Update, Source, RuleChanges, UpdateFile
from update.exceptions import BadFormatError, AbnormalRuleError

class TestUpdate(unittest.TestCase):

	def setUp(self):	   
		# Create source and update objects
		try:
			source = Source.objects.get(name="Manual")
		except Source.DoesNotExist:
			source = Source.objects.create(name="Manual", schedule="00:00", url="", lastMd5="")
	
		self.update = Update.objects.create(time=datetime.datetime.now(), source=source)

	def tearDown(self):
		pass

	def testParseFile(self):
		# Try to add two identical updates with a single rule file. 
		# Should notify that update #2 contains a file with the same
		# hash as the previous.
		ruleFile = "ruleFile2.rules"
		self.update.parseRuleFile(ruleFile)
		try:
			newFile = self.update.source.files.get(name=ruleFile)
		except UpdateFile.DoesNotExist:
			self.fail("Rulefile was not properly created!")
		

	@unittest.skip("Skipping testUpdateRule")
	def testParseRuleFile(self):
		path = os.path.abspath("multilinerules.txt")
		self.update.parseRuleFile(path)
		
		for i in range(1,5):
			sid="200000"+str(i)
			msg="message"+str(i)
			classtype="classtype"+str(i)
			rule = Rule.objects.get(SID=sid)
			self.assertTrue(rule.revisions.latest("rev").rev==i)
			self.assertTrue(rule.revisions.latest("rev").msg==msg)
			self.assertTrue(rule.ruleClass.classtype==classtype)
			
		
	@unittest.skip("Skipping testUpdateRule")
	def testUpdateRule(self):
		# == TEST FOR ABNORMAL RULE DETECTION ==
		print "Testing if AbnormalRuleError is raised for rule with gid != 1"
		rule_gid1 = 'alert udp $EXTERNAL_NET 53 -> $HOME_NET any (msg:"BAD-TRAFFIC TMG Firewall Client long host entry exploit attempt"; sid:19187; gid:1; rev:2; classtype:attempted-user; reference:cve,2011-1889; reference:url,technet.microsoft.com/en-us/security/bulletin/MS11-040; metadata: engine shared, soid 3|19187;)'
		rule_gid3 = 'alert udp $EXTERNAL_NET 53 -> $HOME_NET any (msg:"BAD-TRAFFIC TMG Firewall Client long host entry exploit attempt"; sid:19187; gid:3; rev:2; classtype:attempted-user; reference:cve,2011-1889; reference:url,technet.microsoft.com/en-us/security/bulletin/MS11-040; metadata: engine shared, soid 3|19187;)'
		rule_nogid = 'alert udp $EXTERNAL_NET 53 -> $HOME_NET any (msg:"BAD-TRAFFIC TMG Firewall Client long host entry exploit attempt"; sid:19187; rev:2; classtype:attempted-user; reference:cve,2011-1889; reference:url,technet.microsoft.com/en-us/security/bulletin/MS11-040; metadata: engine shared, soid 3|19187;)'
		path = '/home/echo/rules.rules'
		with self.assertRaises(AbnormalRuleError):
			self.update.updateRule(rule_gid3, path)

		try:
			self.update.updateRule(rule_gid1, path)
			self.update.updateRule(rule_nogid, path)
		except AbnormalRuleError:
			self.fail("AbnormalRuleError raised for normal rule!")

		# == TEST RULECHANGE MECHANISM ==
		rulestring = 'alert tcp $EXTERNAL_NET $FILE_DATA_PORTS -> $HOME_NET any (msg:"BROWSER-WEBKIT Apple Safari SVG Markers Memory Use-After-Free attempt"; flow:to_client,established; file_data; content:"object_whiteList"; fast_pattern:only; content:"shellcode"; nocase; isdataat:600,relative; content:"payload"; distance:0; nocase; content:"shellcode"; within:25; nocase; content:"window.open("; within:50; nocase; content:".svg"; within:25; nocase; metadata:policy balanced-ips drop, policy security-ips drop, service ftp-data, service http, service imap, service pop3; reference:bugtraq,46677; reference:cve,2011-1453; reference:url,support.apple.com/kb/HT4808; classtype:attempted-user; sid:2000000; rev:3;)'
		try:
			Rule.objects.get(SID="2000000").delete()
		except Rule.DoesNotExist:
			pass
		
		# Add rule with ruleset=testset1 then testset2:
		self.update.updateRule(rulestring, "/home/testset1.rules")
		self.update.updateRule(rulestring, "/home/testset2.rules")
		originalSet = RuleSet.objects.get(name="testset1")
		newSet = RuleSet.objects.get(name="testset2")
		
		ruleChange = RuleChanges.objects.get(update_id=self.update.id)
		self.assertTrue(ruleChange.originalSet_id == originalSet.id)
		self.assertTrue(ruleChange.newSet_id == newSet.id)

if __name__ == "__main__":
	#import sys;sys.argv = ['', 'Test.testName']
	unittest.main()