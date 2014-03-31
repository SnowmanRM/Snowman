import datetime
from django.test import TestCase

from core.models import Rule, RuleRevision, Generator, RuleClass, RuleSet, Sensor
from update.models import Source, Update
from tuning.models import DetectionFilter, EventFilter

class Test(TestCase):

	def setUp(self):
		# Create source and update objects
		try:
			source = Source.objects.get(name="Manual")
		except Source.DoesNotExist:
			source = Source.objects.create(name="Manual", schedule="00:00", url="", lastMd5="")

		self.update = Update.objects.create(time=datetime.datetime.now(), source=source)
		
		self.msg = "This is a sample message"
		self.filters = 'detection_filter:track by_src, count 30, seconds 60;threshold:type both, track by_dst, count 10, seconds 60;'
		
		self.rulestring = 'alert tcp any any -> any 21 (\
						msg:"'+self.msg+'"; \
						reference:arachnids,IDS287; reference:bugtraq,1387; reference:cve,CAN-2000-1574; \
						classtype: example-classtype; \
						priority:10; \
						'+self.filters+' \
						metadata:foo bar, ruleset community, bar 1; \
						gid:1; sid:2000000; rev:10)'
						
		self.raw = " ".join('alert tcp any any -> any 21 (\
						msg:"This is a sample message"; \
						reference:arachnids,IDS287; reference:bugtraq,1387; reference:cve,CAN-2000-1574; \
						classtype: example-classtype; \
						priority:10; \
						metadata:foo bar, ruleset community, bar 1; \
						gid:1; sid:2000000; rev:10)'.split())
		
		self.allSensors = Sensor.objects.create(name="All Sensors")
				
		try:
			rule = Rule.objects.get(SID=2000000)
			rule.delete()
		except Rule.DoesNotExist:
			pass


	def tearDown(self):
		pass


	def test_Rule(self):
		# Insert the rule
		self.update.updateRule(self.rulestring, "example.rules")
		
		try:
			# Verify that all related objects exist
			rule = Rule.objects.get(SID=2000000)
			generator = rule.generator
			ruleset = rule.ruleSet
			ruleclass = rule.ruleClass
			revision = rule.revisions.get(rev=10)
			detectionFilter = rule.detectionFilters.get(sensor=self.allSensors)
			eventFilter = rule.eventFilters.get(sensor=self.allSensors)
		except Rule.DoesNotExist:
			self.fail("Rule does not exist")
		except Generator.DoesNotExist:
			self.fail("Generator does not exist")
		except RuleSet.DoesNotExist:
			self.fail("RuleSet does not exist")
		except RuleClass.DoesNotExist:
			self.fail("RuleClass does not exist")
		except RuleRevision.DoesNotExist:
			self.fail("RuleRevision does not exist")
		except DetectionFilter.DoesNotExist:
			self.fail("DetectionFilter does not exist")
		except EventFilter.DoesNotExist:
			self.fail("EventFilter does not exist")	
		
		self.assertTrue(rule.active==True)
		self.assertTrue(int(rule.priority)==10)
		
		# Check revision object:
		# 1: Check that filters are extracted
		self.assertTrue(revision.raw==self.raw)
		self.assertTrue(revision.msg==self.msg)
		self.assertTrue(revision.active==True)
		self.assertTrue(revision.filters==self.filters)
