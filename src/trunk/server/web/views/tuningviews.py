from django.http import Http404, HttpResponse
from django.shortcuts import render, redirect

from core.models import Rule, RuleRevision, Sensor, Generator
from tuning.models import Threshold, Suppress, SuppressAddress
from web.utilities import UserSettings
import logging, json, re


def getThresholdForm(request):
	"""This method is loaded when the /tuning/getThresholdForm is called. 
	It delivers a form for thresholding. """
	
	logger = logging.getLogger(__name__)
	
	context = {}
	
	try:
	# Get a complete list of sensors.
	
		context['allsensors'] = Sensor.objects.all()
	
	except Sensor.DoesNotExist:
		logger.warning("No sensors found.")
		raise Http404
	
	# Send to template.
	return render(request, 'tuning/thresholdForm.tpl', context)

def getSuppressForm(request):
	"""This method is loaded when the /tuning/getSuppressForm is called. 
	It delivers a form for suppression. """
	
	logger = logging.getLogger(__name__)
	
	context = {}
	
	try:
	# Get a complete list of sensors..
	
		context['allsensors'] = Sensor.objects.all()
	
	except Sensor.DoesNotExist:
		logger.warning("No sensors found.")
		raise Http404
	
	# Send to template.
	return render(request, 'tuning/suppressForm.tpl', context)

def modifyRule(request):
	logger = logging.getLogger(__name__)
	
	sids = json.loads(request.POST.get('sids'))
	mode = json.loads(request.POST.get('mode'))
	
	if mode == "enable":
		active = True
	elif mode == "disable":
		active = False
	else:
		logger.error("Invalid mode '"+mode+"'. Rule(s) not modified.")
		return

	for sid in sids:
		r = Rule.objects.get(SID=sid)
		r.active = active
		r.save()
		logger.info("Rule "+str(r)+" is now "+mode+"d.")
		
	return HttpResponse("json.dumps(response)")

def setThresholdOnRule(request):
	"""This method is loaded when the /tuning/setThresholdOnRule is called.
	The request should contain a POST of a form with all required fields. 
	
	The function will check all values for errors and return a warning if something isnt right.
	
	If everything is ok or the force flag is set, it will either update or create the Threshold objects requested.
	"""
	
	# Get some initial post values for processing.
	ruleIds = request.POST.getlist('id')
	sensors = request.POST.getlist('sensors')
	commentString = request.POST['comment']
	force = request.POST['force']
	response = []
	
	# If the ruleIds list is empty, it means a SID has been entered manually.
	if len(ruleIds) == 0:
		# Grab the value from the POST.
		ruleSID = request.POST['sid']
		
		# Match the GID:SID pattern, if its not there, throw exception.
		try:
			matchPattern = r"(\d+):(\d+)"
			pattern = re.compile(matchPattern)
			result = pattern.match(ruleSID)
			
			ruleGID = result.group(1)
			ruleSID = result.group(2)
		except:
			response.append({'response': 'invalidGIDSIDFormat', 'text': 'Please format in the GID:SID syntax.'})
			return HttpResponse(json.dumps(response))
		
		# Try to find a generator object with the GID supplied, if it doesnt exist, throw exception.
		try:
			g = Generator.objects.filter(GID=ruleGID).count() # There might be more than one.
			if g == 0:
				response.append({'response': 'gidDoesNotExist', 'text': 'GID '+ruleGID+' does not exist.'})
				return HttpResponse(json.dumps(response))
		except Generator.DoesNotExist:
			response.append({'response': 'gidDoesNotExist', 'text': 'GID '+ruleGID+' does not exist.'})
			return HttpResponse(json.dumps(response))
		
		# Try to find a rule object with the SID supplied, if it doesnt exist, throw exception.
		try:
			ruleIds.append(Rule.objects.get(SID=ruleSID).id)
		except Rule.DoesNotExist:
			response.append({'response': 'sidDoesNotExist', 'text': 'SID '+ruleSID+' does not exist.'})
			return HttpResponse(json.dumps(response))
		
	# If force is false, it means we have to check everything.				
	if force == "False":
				
		sensorList = []
		
		# If we didnt pick all sensors, we gotta check to see if the selected ones exist. 
		# We also populate a list for later use.
		if sensors[0] != "all":
			for sensor in sensors:
				sensorList.append(sensor)
				try:
					Sensor.objects.get(id=sensor)
				except Sensor.DoesNotExist:
					response.append({'response': 'sensorDoesNotExist', 'text': 'Sensor with DB ID '+sensor+' does not exist.'})
					return HttpResponse(json.dumps(response))
		# If we selected all sensors, generate a list of all of their ids.	
		elif sensors[0] == "all":
			sensorList = Sensor.objects.values_list('id', flat=True)
		
		# We iterate through all selected sensors and rules to see if a threshold already exists.
		# We warn the user if there are thresholds. We also check to see if the rule objects selected exist. 	
		for sensor in sensorList:
			s = Sensor.objects.get(id=sensor)
			for ruleId in ruleIds:
				try:
					r = Rule.objects.get(id=ruleId)
					if r.thresholds.filter(sensor=s).count() > 0:
						if len(response) == 0:
							response.append({'response': 'thresholdExists', 'text': 'Thresholds already exists, do you want to overwrite?.', 'sids': []})
						response[0]['sids'].append(r.SID)
						response[0]['sids']=list(set(response[0]['sids']))
				except Rule.DoesNotExist:
					response.append({'response': 'ruleDoesNotExist', 'text': 'Rule with DB ID '+ruleId+' does not exist.'})
					return HttpResponse(json.dumps(response))
			
		# Warn the user if the comment string is empty.
		if commentString == "":
			response.append({'response': 'noComment', 'text': 'You have not set any comments on this action, are you sure you want to proceed?.'})
		
		# Warn the user since all sensors is default.
		if sensors[0] == "all":
			response.append({'response': 'allSensors', 'text': 'You are setting this threshold on all sensors, are you sure you want to do that?.'})
		
		# If any responses were triggered, return them. Else, we set force to true and implement the threshold.
		if len(response) > 0:
			return HttpResponse(json.dumps(response))
		else:
			force="True"
	
	# The user either wants us to continue or there were no warnings.
	if force == "True":
		tcount = int(request.POST['count'])
		tseconds = int(request.POST['seconds'])
		
		ttype = int(request.POST['type'])
		
		# We make sure type is in the correct range.
		if ttype not in range(1,4):
			response.append({'response': 'typeOutOfRange', 'text': 'Type value out of range.'})
			return HttpResponse(json.dumps(response))
	
		ttrack = int(request.POST['track'])
		
		# We make sure track is in the correct range.
		if ttrack not in range(1,3):
			response.append({'response': 'trackOutOfRange', 'text': 'Track value out of range.'})
			return HttpResponse(json.dumps(response))
		
		# If we selected all sensors, generate a list of all of their ids.
		if sensors[0] == "all":
			sensors = Sensor.objects.values_list('id', flat=True)
		
		# We iterate over all the rules and sensors to implement the threshold.
		try:
			for ruleId in ruleIds:
				for sensorId in sensors:
					trule = Rule.objects.get(id=ruleId)
					tsensor = Sensor.objects.get(id=sensorId)
					# We check to see if a threshold already exists, in that case we just update it. If not, we create one.
					t = Threshold.objects.filter(rule=trule, sensor=tsensor).count();
					if t > 0:
						Threshold.objects.filter(rule=trule, sensor=tsensor).update(comment=commentString, thresholdType=ttype, track=ttrack, count=tcount, seconds=tseconds)
					elif t == 0:
						t = Threshold(rule=trule, sensor=tsensor, comment=commentString, thresholdType=ttype, track=ttrack, count=tcount, seconds=tseconds)
						t.save()
			
			response.append({'response': 'thresholdAdded', 'text': 'Threshold successfully added.'})
			return HttpResponse(json.dumps(response))
		except: # Something went wrong.
			response.append({'response': 'addThresholdFailure', 'text': 'Failed when trying to add thresholds.'})
			return HttpResponse(json.dumps(response))
		
def setSuppressOnRule(request):
	"""This method is loaded when the /tuning/setSuppressOnRule is called.
	The request should contain a POST of a form with all required fields. 
	
	The function will check all values for errors and return a warning if something isnt right.
	
	If everything is ok or the force flag is set, it will either update or create the Suppress objects requested.
	"""
	
	# Get some initial post values for processing.
	ruleIds = request.POST.getlist('id')
	sensors = request.POST.getlist('sensors')
	commentString = request.POST['comment']
	force = request.POST['force']
	response = []
	
	# If the ruleIds list is empty, it means a SID has been entered manually.
	if len(ruleIds) == 0:
		# Grab the value from the POST.
		ruleSID = request.POST['sid']
		
		# Match the GID:SID pattern, if its not there, throw exception.
		try:
			matchPattern = r"(\d+):(\d+)"
			pattern = re.compile(matchPattern)
			result = pattern.match(ruleSID)
			
			ruleGID = result.group(1)
			ruleSID = result.group(2)
		except:
			response.append({'response': 'invalidGIDSIDFormat', 'text': 'Please format in the GID:SID syntax.'})

			return HttpResponse(json.dumps(response))
		
		# Try to find a generator object with the GID supplied, if it doesnt exist, throw exception.
		try:
			g = Generator.objects.filter(GID=ruleGID).count() # There might be more than one.
			if g == 0:
				response.append({'response': 'gidDoesNotExist', 'text': 'GID '+ruleGID+' does not exist.'})
				return HttpResponse(json.dumps(response))
		except Generator.DoesNotExist:
			response.append({'response': 'gidDoesNotExist', 'text': 'GID '+ruleGID+' does not exist.'})
			return HttpResponse(json.dumps(response))
		
		# Try to find a rule object with the SID supplied, if it doesnt exist, throw exception.
		try:
			ruleIds.append(Rule.objects.get(SID=ruleSID).id)
		except Rule.DoesNotExist:
			response.append({'response': 'sidDoesNotExist', 'text': 'SID '+ruleSID+' does not exist.'})
			return HttpResponse(json.dumps(response))
	
	# If force is false, it means we have to check everything.	
	if force == "False":
		
		sensorList = []
		
		# If we didnt pick all sensors, we gotta check to see if the selected ones exist. 
		# We also populate a list for later use.
		if sensors[0] != "all":
			for sensor in sensors:
				sensorList.append(sensor)
				try:
					Sensor.objects.get(id=sensor)
				except Sensor.DoesNotExist:
					response.append({'response': 'sensorDoesNotExist', 'text': 'Sensor with DB ID '+sensor+' does not exist.'})
					return HttpResponse(json.dumps(response))	
		# If we selected all sensors, generate a list of all of their ids.
		elif sensors[0] == "all":
			sensorList = Sensor.objects.values_list('id', flat=True)
			
		# We iterate through all selected sensors and rules to see if a threshold already exists.
		# We warn the user if there are thresholds. We also check to see if the rule objects selected exist. 	
		for sensor in sensorList:
			s = Sensor.objects.get(id=sensor)
			for ruleId in ruleIds:
				try:
					r = Rule.objects.get(id=ruleId)
					if r.suppress.filter(sensor=s).count() > 0:
						if len(response) == 0:
							response.append({'response': 'suppressExists', 'text': 'Suppressions already exists, do you want to overwrite?.', 'sids': []})
						response[0]['sids'].append(r.SID)
						response[0]['sids']=list(set(response[0]['sids']))
				except Rule.DoesNotExist:
					response.append({'response': 'ruleDoesNotExist', 'text': 'Rule with DB ID '+ruleId+' does not exist.'})
					return HttpResponse(json.dumps(response))
		
		# Since this form lets the user input one or more IPv4 addresses, we have to check them.
		ipString = request.POST['ip']
		
		# The string cant be empty.
		if ipString == "":
			response.append({'response': 'noIPGiven', 'text': 'You need to supply one or more IP addresses.'})
			return HttpResponse(json.dumps(response))
		
		badIps = []
		badIpTest = False
		
		# This pattern matches for valid IPv4 with subnet notation (0.0.0.0/0 - 255.255.255.255/32).
		ipPattern = re.compile("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/([0-9]|[12]?[0-9]|3[0-2])|)$")
		
		# Iterate over each IP given and check it for validity.
		for ip in re.finditer("[^,;\s]+", ipString):
			test = ipPattern.match(ip.group(0))
			if not test:
				badIps.append(ip.group(0))
				badIpTest = True
		
		# Express error if one of the IPs is invalid as IPv4.
		if badIpTest:
			response.append({'response': 'badIP', 'text': 'is not valid IPv4.', 'ips': badIps})
			
		# Warn the user if the comment string is empty.
		if commentString == "":
			response.append({'response': 'noComment', 'text': 'You have not set any comments on this action, are you sure you want to proceed?.'})
		
		# Warn the user since all sensors is default.
		if sensors[0] == "all":
			response.append({'response': 'allSensors', 'text': 'You are setting this suppression on all sensors, are you sure you want to do that?.'})
		
		# If any responses were triggered, return them. Else, we set force to true and implement the threshold.
		if len(response) > 0:
			return HttpResponse(json.dumps(response))
		else:
			force="True"
	
	# The user either wants us to continue or there were no warnings.
	if force == "True":
		strack = int(request.POST['track'])
		
		# We make sure track is in the correct range.
		if strack not in range(1,3):
			response.append({'response': 'trackOutOfRange', 'text': 'Track value out of range.'})
			return HttpResponse(json.dumps(response))
		
		# If we selected all sensors, generate a list of all of their ids.
		if sensors[0] == "all":
			sensors = Sensor.objects.values_list('id', flat=True)
		
		# We do the IP matching again since we could have submitted them again since last check.
		# Since this form lets the user input one or more IPv4 addresses, we have to check them.
		ipString = request.POST['ip']
		
		# The string cant be empty.
		if ipString == "":
			response.append({'response': 'noIPGiven', 'text': 'You need to supply one or more IP addresses.'})
			return HttpResponse(json.dumps(response))
		
		goodIps = []
		
		# This pattern matches for valid IPv4 with subnet notation (0.0.0.0/0 - 255.255.255.255/32).
		ipPattern = re.compile("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/([0-9]|[12]?[0-9]|3[0-2])|)$")
		
		# Iterate over each IP given and check it for validity.
		# We put it in the list we use for making SuppressAddresses later.
		for ip in re.finditer("[^,;\s]+", ipString):
			test = ipPattern.match(ip.group(0))
			if test:
				goodIps.append(ip.group(0))
				
		suppressAddressList = []
		
		# We iterate over all IPs that were good and create SuppressAddress objects and put them in the 
		# suppressAddressList we use for creating Suppress objects later.
		# We also check if the IP already has a SuppressAddress object and just put that in the suppressAddressList.
		try:
			for ip in goodIps:
				sa = SuppressAddress.objects.filter(ipAddress=ip).count()
				if sa > 0:
					suppressAddressList.append(SuppressAddress.objects.get(ipAddress=ip))
				else:
					sa = SuppressAddress.objects.create(ipAddress=ip)
					suppressAddressList.append(sa)
				
		except:
			response.append({'response': 'addSuppressAddressFailure', 'text': 'Failed when trying to add suppression addresses.'})
			return HttpResponse(json.dumps(response))
		
		# We iterate over all the rules and sensors to implement the suppression.
		try:
			for ruleId in ruleIds:
				for sensorId in sensors:
					srule = Rule.objects.get(id=ruleId)
					ssensor = Sensor.objects.get(id=sensorId)
					# We check to see if a suppression already exists, in that case we just update it. If not, we create one.
					s = Suppress.objects.filter(rule=srule, sensor=ssensor).count();
					if s > 0:
						Suppress.objects.filter(rule=srule, sensor=ssensor).update(comment=commentString, track=strack)
						s = Suppress.objects.get(rule=srule, sensor=ssensor)
						for address in suppressAddressList:
							s.addresses.add(address)
					elif s == 0:
						s = Suppress.objects.create(rule=srule, sensor=ssensor, comment=commentString, track=strack)
						for address in suppressAddressList:
							s.addresses.add(address)
			
			response.append({'response': 'suppressAdded', 'text': 'Suppression successfully added.'})
			return HttpResponse(json.dumps(response))
		except: # Something went wrong.
			response.append({'response': 'addSuppressFailure', 'text': 'Failed when trying to add suppressions.'})
			return HttpResponse(json.dumps(response))

