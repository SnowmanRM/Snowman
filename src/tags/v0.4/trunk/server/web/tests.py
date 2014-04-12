import json
from django.test import TestCase
from django.test import Client
from core.models import Sensor, Generator, RuleReferenceType, RuleSet, RuleClass, Rule
from update.models import Source
from django.contrib.auth.models import User
from tuning.models import EventFilter, DetectionFilter

class FilterTests(TestCase):
	def setUp(self):
		# Every test needs a client.
		self.client = Client()
		
		user = User.objects.create(username = "testuser", first_name = "User", last_name = "Test")
		self.sensor = Sensor.objects.create(name="testsensor", user=user, active=True, ipAddress="")
		self.sensor2 = Sensor.objects.create(name="testsensor2", user=user, active=True, ipAddress="")
		generator = Generator.objects.create(GID=1, alertID=1, message="Generic SNORT rule")
		ruleset = RuleSet.objects.create(name="testruleset",description="desc",active=True)
		ruleclass = RuleClass.objects.create(classtype="testclasstype", description="desc", priority=1)
		self.rule = Rule.objects.create(SID=2000, active=True, generator=generator, ruleSet=ruleset, ruleClass=ruleclass)
		source = Source.objects.get_or_create(name = "Manual")

	def test_AddEventFilter(self):
		# Create an eventFilter
		page = '/web/tuning/setFilterOnRule/'
		data = {'comment':'no comment','force':'False','sid':'1:2000', 'sensors':[self.sensor.id], 'filterType':'eventFilter', 'count':'5', 'seconds':'5', 'type':'1', 'track':'1'}
		print "Sending request for new EventFilter"
		self.sendRequest(page, data, "filterAdded")
		
		try:
			f = EventFilter.objects.get(rule=self.rule, sensor=self.sensor)
			f.delete()
		except EventFilter.DoesNotExist:
			self.fail("EventFilter was NOT created.")	
		
	def test_AddDetectionFilter(self):
		# Create an detectionFilter
		page = '/web/tuning/setFilterOnRule/'
		data = {'comment':'no comment','force':'False','sid':'1:2000', 'sensors':[self.sensor.id], 'filterType':'detectionFilter', 'count':'5', 'seconds':'5', 'type':'1', 'track':'1'}
		print "Sending request for new DetectionFilter"
		self.sendRequest(page, data, "filterAdded")

		try:
			f = DetectionFilter.objects.get(rule=self.rule, sensor=self.sensor)
			f.delete()
		except DetectionFilter.DoesNotExist:
			self.fail("DetectionFilter was NOT created.")
			
	def sendRequest(self, page, data, reply):
		response = self.client.post(page, data)
		responseText = json.loads(response.content)[0]["response"]
		print "Got response: "+responseText
		self.assertTrue(responseText == reply)
		