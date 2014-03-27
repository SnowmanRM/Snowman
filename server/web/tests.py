import unittest, json
from django.test import Client
from core.models import Sensor, Generator, RuleReferenceType, RuleSet, RuleClass, Rule
from update.models import Source
from django.contrib.auth.models import User

class SimpleTest(unittest.TestCase):
	def setUp(self):
		# Every test needs a client.
		self.client = Client()
		
		user = User.objects.create(username = "testuser", first_name = "User", last_name = "Test")
		self.sensor = Sensor.objects.create(name="testsensor", user=user, active=True, ipAddress="")
		generator = Generator.objects.create(GID=1, alertID=1, message="Generic SNORT rule")
		ruleset = RuleSet.objects.create(name="testruleset",description="desc",active=True)
		ruleclass = RuleClass.objects.create(classtype="testclasstype", description="desc", priority=1)
		rule = Rule.objects.create(SID=2000, active=True, generator=generator, ruleSet=ruleset, ruleClass=ruleclass)
		source = Source.objects.get_or_create(name = "Manual")

	def test_details(self):
		response = self.client.post('/web/tuning/setFilterOnRule/', {'comment':'no comment','force':'False','sid':'1:2000', 'sensors':[self.sensor.id], 'filterType':'eventFilter', 'count':'5', 'seconds':'5', 'type':'1', 'track':'1'})
		print json.loads(response.content)[0]["response"]
		print str(response)
		self.assertTrue(json.loads(response.content)[0]["response"] == "filterAdded")
		